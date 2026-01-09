import json
import logging
import os
from unique_random_slugs import generate_slug
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from typing import Callable, List, Tuple

import prettytable
from termcolor import colored

import testcases
from result import TestResult
from testcases import Perspective


class MeasurementResult:
    result = TestResult
    details = str
    raw_data = None


class LogFileFormatter(logging.Formatter):
    def format(self, record):
        msg = super(LogFileFormatter, self).format(record)
        # remove color control characters
        return re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]").sub("", msg)


class InteropRunner:
    _start_time = 0
    test_results = {}
    measurement_results = {}
    compliant = {}
    _implementations = {}
    _client_server_pairs = []
    _tests = []
    _measurements = []
    _output = ""
    _markdown = False
    _log_dir = ""
    _save_files = False
    _no_auto_unsupported = []
    _protocol = "quic"
    _scenario = "simple"
    _file_size = None

    def __init__(
        self,
        implementations: dict,
        client_server_pairs: List[Tuple[str, str]],
        tests: List[testcases.TestCase],
        measurements: List[testcases.Measurement],
        output: str,
        markdown: bool,
        debug: bool,
        save_files=False,
        log_dir="",
        no_auto_unsupported=[],
        protocol="quic",
        scenario="simple",
        file_size=None,
    ):
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        console = logging.StreamHandler(stream=sys.stderr)
        if debug:
            console.setLevel(logging.DEBUG)
        else:
            console.setLevel(logging.INFO)
        logger.addHandler(console)
        self._start_time = datetime.now()
        self._tests = tests
        self._measurements = measurements
        self._client_server_pairs = client_server_pairs
        self._implementations = implementations
        self._output = output
        self._markdown = markdown
        self._log_dir = log_dir
        self._save_files = save_files
        self._no_auto_unsupported = no_auto_unsupported
        self._protocol = protocol
        self._file_size = file_size
        self._scenario = scenario
        if len(self._log_dir) == 0:
            self._log_dir = "logs_{:%Y-%m-%dT%H:%M:%S}".format(self._start_time)
        if os.path.exists(self._log_dir):
            sys.exit("Log dir " + self._log_dir + " already exists.")
        logging.info("Saving logs to %s.", self._log_dir)
        for client, server in client_server_pairs:
            for test in self._tests:
                self.test_results.setdefault(server, {}).setdefault(
                    client, {}
                ).setdefault(test, {})
            for measurement in measurements:
                self.measurement_results.setdefault(server, {}).setdefault(
                    client, {}
                ).setdefault(measurement, {})

    def _sample_container_stats(self, container_name: str, stats_list: list, stop_event: threading.Event, interval: float = 0.5):
        """Sample container CPU and memory stats in background."""
        while not stop_event.is_set():
            try:
                # Get container ID
                cmd = f"docker ps --format '{{{{.ID}}}} {{{{.Names}}}}' | awk '/^.* {container_name}$/ {{print $1}}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1)
                
                if result.returncode != 0 or not result.stdout.strip():
                    time.sleep(interval)
                    continue
                
                container_id = result.stdout.strip()
                
                # Get stats with longer timeout
                cmd = f"docker stats {container_id} --no-stream --format '{{{{.CPUPerc}}}},{{{{.MemUsage}}}}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0 and result.stdout.strip():
                    stats_line = result.stdout.strip()
                    parts = stats_line.split(',')
                    if len(parts) == 2:
                        cpu_str = parts[0].replace('%', '').strip()
                        mem_str = parts[1].split('/')[0].strip()
                        
                        try:
                            cpu_percent = float(cpu_str)
                        except ValueError:
                            cpu_percent = None
                        
                        mem_mb = None
                        if 'MiB' in mem_str:
                            mem_mb = float(mem_str.replace('MiB', ''))
                        elif 'GiB' in mem_str:
                            mem_mb = float(mem_str.replace('GiB', '')) * 1024
                        elif 'KiB' in mem_str:
                            mem_mb = float(mem_str.replace('KiB', '')) / 1024
                        
                        if cpu_percent is not None and mem_mb is not None:
                            stats_list.append({
                                'timestamp': time.time(),
                                'cpu_percent': cpu_percent,
                                'memory_mb': mem_mb
                            })
                
            except subprocess.TimeoutExpired:
                pass  # Silently skip timeout - container might be starting/stopping
            except Exception as e:
                logging.debug("Error sampling container stats: %s", e)
            
            time.sleep(interval)

    def _aggregate_stats(self, stats_list: list) -> dict:
        if not stats_list:
            return {
                'cpu_mean': None,
                'cpu_peak': None,
                'memory_mean': None,
                'memory_peak': None
            }
        
        cpu_values = [s['cpu_percent'] for s in stats_list]
        mem_values = [s['memory_mb'] for s in stats_list]
        
        return {
            'cpu_mean': statistics.mean(cpu_values),
            'cpu_peak': max(cpu_values),
            'memory_mean': statistics.mean(mem_values),
            'memory_peak': max(mem_values),
            'sample_count': len(stats_list)
        }

    def _is_unsupported(self, lines: List[str]) -> bool:
        return any("exited with code 127" in str(line) for line in lines) or any(
            "exit status 127" in str(line) for line in lines
        )

    def _check_impl_is_compliant(self, name: str) -> bool:
        """check if an implementation return UNSUPPORTED for unknown test cases"""
        logging.debug("Protocol: %s", self._protocol)
        if self._protocol == "tcp":
            # TCP implementations are generic and don't support testcase-specific exit codes
            return True
        if name in self.compliant:
            logging.debug(
                "%s already tested for compliance: %s", name, str(self.compliant)
            )
            return self.compliant[name]

        client_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_client_")
        www_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="compliance_www_")
        certs_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="compliance_certs_")
        downloads_dir = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="compliance_downloads_"
        )

        testcases.generate_cert_chain(certs_dir.name)

        # check that the client is capable of returning UNSUPPORTED
        logging.debug("Checking compliance of %s client", name)
        cmd = (
            "CERTS=" + certs_dir.name + " "
            "TESTCASE_CLIENT=" + generate_slug() + " "
            "SERVER_LOGS=/dev/null "
            "CLIENT_LOGS=" + client_log_dir.name + " "
            "WWW=" + www_dir.name + " "
            "DOWNLOADS=" + downloads_dir.name + " "
            'SCENARIO="simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25" '
            "CLIENT=" + self._implementations[name]["image"] + " "
            "SERVER="
            + self._implementations[name]["image"]
            + " "  # only needed so docker compose doesn't complain
            "docker compose --env-file empty.env up --timeout 0 --abort-on-container-exit -V sim client"
        )
        output = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        if not self._is_unsupported(output.stdout.splitlines()):
            logging.error("%s client not compliant.", name)
            logging.debug("%s", output.stdout.decode("utf-8", errors="replace"))
            self.compliant[name] = False
            return False
        logging.debug("%s client compliant.", name)

        # check that the server is capable of returning UNSUPPORTED
        logging.debug("Checking compliance of %s server", name)
        server_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_server_")
        cmd = (
            "CERTS=" + certs_dir.name + " "
            "TESTCASE_SERVER=" + generate_slug() + " "
            "SERVER_LOGS=" + server_log_dir.name + " "
            "CLIENT_LOGS=/dev/null "
            "WWW=" + www_dir.name + " "
            "DOWNLOADS=" + downloads_dir.name + " "
            "CLIENT="
            + self._implementations[name]["image"]
            + " "  # only needed so docker compose doesn't complain
            "SERVER=" + self._implementations[name]["image"] + " "
            "docker compose --env-file empty.env up -V server"
        )
        output = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        if not self._is_unsupported(output.stdout.splitlines()):
            logging.error("%s server not compliant.", name)
            logging.debug("%s", output.stdout.decode("utf-8", errors="replace"))
            self.compliant[name] = False
            return False
        logging.debug("%s server compliant.", name)

        # remember compliance test outcome
        self.compliant[name] = True
        return True

    def _postprocess_results(self):
        clients = list(set(client for client, _ in self._client_server_pairs))
        servers = list(set(server for _, server in self._client_server_pairs))
        questionable = [TestResult.FAILED, TestResult.UNSUPPORTED]
        # If a client failed a test against all servers, make the test unsupported for the client
        if len(servers) > 1:
            for c in set(clients) - set(self._no_auto_unsupported):
                for t in self._tests:
                    if all(self.test_results[s][c][t] in questionable for s in servers):
                        print(
                            f"Client {c} failed or did not support test {t.name()} "
                            + 'against all servers, marking the entire test as "unsupported"'
                        )
                        for s in servers:
                            self.test_results[s][c][t] = TestResult.UNSUPPORTED
        # If a server failed a test against all clients, make the test unsupported for the server
        if len(clients) > 1:
            for s in set(servers) - set(self._no_auto_unsupported):
                for t in self._tests:
                    if all(self.test_results[s][c][t] in questionable for c in clients):
                        print(
                            f"Server {s} failed or did not support test {t.name()} "
                            + 'against all clients, marking the entire test as "unsupported"'
                        )
                        for c in clients:
                            self.test_results[s][c][t] = TestResult.UNSUPPORTED

    def _print_results(self):
        """print the interop table"""
        logging.info("Run took %s", datetime.now() - self._start_time)

        def get_letters(result):
            return (
                result.symbol()
                + "("
                + ",".join(
                    [test.abbreviation() for test in cell if cell[test] is result]
                )
                + ")"
            )

        if len(self._tests) > 0:
            t = prettytable.PrettyTable()
            if self._markdown:
                t.set_style(prettytable.MARKDOWN)
            else:
                t.hrules = prettytable.ALL
                t.vrules = prettytable.ALL
            rows = {}
            columns = {}
            for client, server in self._client_server_pairs:
                columns[server] = {}
                row = rows.setdefault(client, {})
                cell = self.test_results[server][client]
                br = "<br>" if self._markdown else "\n"
                res = colored(get_letters(TestResult.SUCCEEDED), "green") + br
                res += colored(get_letters(TestResult.UNSUPPORTED), "grey") + br
                res += colored(get_letters(TestResult.FAILED), "red")
                row[server] = res

            t.field_names = [""] + [column for column, _ in columns.items()]
            for client, results in rows.items():
                row = [client]
                for server, _ in columns.items():
                    row += [results.setdefault(server, "")]
                t.add_row(row)
            print(t)

        if len(self._measurements) > 0:
            t = prettytable.PrettyTable()
            if self._markdown:
                t.set_style(prettytable.MARKDOWN)
            else:
                t.hrules = prettytable.ALL
                t.vrules = prettytable.ALL
            rows = {}
            columns = {}
            for client, server in self._client_server_pairs:
                columns[server] = {}
                row = rows.setdefault(client, {})
                cell = self.measurement_results[server][client]
                results = []
                for measurement in self._measurements:
                    res = cell[measurement]
                    if not hasattr(res, "result"):
                        continue
                    if res.result == TestResult.SUCCEEDED:
                        results.append(
                            colored(
                                measurement.abbreviation() + ": " + res.details,
                                "green",
                            )
                        )
                    elif res.result == TestResult.UNSUPPORTED:
                        results.append(colored(measurement.abbreviation(), "grey"))
                    elif res.result == TestResult.FAILED:
                        results.append(colored(measurement.abbreviation(), "red"))
                row[server] = "\n".join(results)
            t.field_names = [""] + [column for column, _ in columns.items()]
            for client, results in rows.items():
                row = [client]
                for server, _ in columns.items():
                    row += [results.setdefault(server, "")]
                t.add_row(row)
            print(t)

    def _export_results(self):
        if not self._output:
            return
        clients = list(set(client for client, _ in self._client_server_pairs))
        servers = list(set(server for _, server in self._client_server_pairs))
        out = {
            "start_time": self._start_time.timestamp(),
            "end_time": datetime.now().timestamp(),
            "log_dir": self._log_dir,
            "servers": servers,
            "clients": clients,
            "urls": {x: self._implementations[x]["url"] for x in clients + servers},
            "tests": {
                x.abbreviation(): {
                    "name": x.name(),
                    "desc": x.desc(),
                }
                for x in self._tests + self._measurements
            },
            "quic_draft": testcases.QUIC_DRAFT,
            "quic_version": testcases.QUIC_VERSION,
            "results": [],
            "measurements": [],
        }

        for client in clients:
            for server in servers:
                results = []
                for test in self._tests:
                    r = None
                    if hasattr(self.test_results[server][client][test], "value"):
                        r = self.test_results[server][client][test].value
                    results.append(
                        {
                            "abbr": test.abbreviation(),
                            "name": test.name(),  # TODO: remove
                            "result": r,
                        }
                    )
                out["results"].append(results)

                measurements = []
                for measurement in self._measurements:
                    res = self.measurement_results[server][client][measurement]
                    if not hasattr(res, "result"):
                        continue
                    
                    measurement_data = {
                        "name": measurement.name(),
                        "abbr": measurement.abbreviation(),
                        "result": res.result.value,
                        "details": res.details,
                    }
                    
                    # Include raw structured data if available
                    if hasattr(res, "raw_data") and res.raw_data is not None:
                        measurement_data["data"] = res.raw_data
                    
                    measurements.append(measurement_data)
                out["measurements"].append(measurements)

        f = open(self._output, "w")
        json.dump(out, f)
        f.close()

    def _copy_logs(self, container: str, dir: tempfile.TemporaryDirectory):
        cmd = (
            "docker cp \"$(docker ps -a --format '{{.ID}} {{.Names}}' | awk '/^.* "
            + container
            + "$/ {print $1}')\":/logs/. "
            + dir.name
        )
        r = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if r.returncode != 0:
            logging.info(
                "Copying logs from %s failed: %s",
                container,
                r.stdout.decode("utf-8", errors="replace"),
            )

    def _run_testcase(
        self, server: str, client: str, test: Callable[[], testcases.TestCase]
    ) -> TestResult:
        return self._run_test(server, client, None, test)[0]

    def _run_test(
        self,
        server: str,
        client: str,
        log_dir_prefix: None,
        test: Callable[[], testcases.TestCase],
    ) -> Tuple[TestResult, float, dict]:
        start_time = datetime.now()
        sim_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_sim_")
        server_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_server_")
        client_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_client_")
        log_file = tempfile.NamedTemporaryFile(dir="/tmp", prefix="output_log_")
        log_handler = logging.FileHandler(log_file.name)
        log_handler.setLevel(logging.DEBUG)

        formatter = LogFileFormatter("%(asctime)s %(message)s")
        log_handler.setFormatter(formatter)
        logging.getLogger().addHandler(log_handler)

        testcase = test(
            sim_log_dir=sim_log_dir,
            client_keylog_file=client_log_dir.name + "/keys.log",
            server_keylog_file=server_log_dir.name + "/keys.log",
            protocol=self._protocol,
            file_size=self._file_size,
        )

        print(
            "Server: "
            + server
            + ". Client: "
            + client
            + ". Running test case: "
            + str(testcase)
        )

        reqs = " ".join([testcase.urlprefix() + p for p in testcase.get_paths()])
        logging.debug("Requests: %s", reqs)
        port = "443" if self._protocol == "quic" else "80"
        waitforserver = "WAITFORSERVER=server:" + port + " " if self._protocol == "quic" else ""
        params = (
            "PROTOCOL=" + self._protocol + " "
            + waitforserver +
            "CERTS=" + testcase.certs_dir() + " "
            "TESTCASE_SERVER=" + testcase.testname(Perspective.SERVER) + " "
            "TESTCASE_CLIENT=" + testcase.testname(Perspective.CLIENT) + " "
            "WWW=" + testcase.www_dir() + " "
            "DOWNLOADS=" + testcase.download_dir() + " "
            "SERVER_LOGS=" + server_log_dir.name + " "
            "CLIENT_LOGS=" + client_log_dir.name + " "
            'SCENARIO="{}" '
            "CLIENT=" + self._implementations[client]["image"] + " "
            "SERVER=" + self._implementations[server]["image"] + " "
            'REQUESTS="' + reqs + '" '
        ).format(testcase.scenario())
        params += " ".join(testcase.additional_envs())
        containers = "sim client server " + " ".join(testcase.additional_containers())
        cmd = (
            params
            + " docker compose --env-file empty.env up --abort-on-container-exit --timeout 1 "
            + containers
        )
        logging.debug("Command: %s", cmd)

        server_stats = []
        client_stats = []
        stop_stats = threading.Event()
        stats_threads_started = False

        status = TestResult.FAILED
        output = ""
        expired = False
        
        # Start docker compose in background
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        
        # Wait a bit for containers to start, then begin stats collection
        time.sleep(2)  # Give containers time to start
        
        server_stats_thread = threading.Thread(
            target=self._sample_container_stats,
            args=("server", server_stats, stop_stats, 0.5),
            daemon=True
        )
        client_stats_thread = threading.Thread(
            target=self._sample_container_stats,
            args=("client", client_stats, stop_stats, 0.5),
            daemon=True
        )
        
        server_stats_thread.start()
        client_stats_thread.start()
        stats_threads_started = True
        
        try:
            output, _ = proc.communicate(timeout=testcase.timeout())
        except subprocess.TimeoutExpired:
            output, _ = proc.communicate()
            expired = True
        finally:
            # Stop stats collection
            if stats_threads_started:
                stop_stats.set()
                server_stats_thread.join(timeout=2)
                client_stats_thread.join(timeout=2)

        logging.debug("%s", output.decode("utf-8", errors="replace"))

        if expired:
            logging.debug("Test failed: took longer than %ds.", testcase.timeout())
            r = subprocess.run(
                "docker compose --env-file empty.env stop " + containers,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=60,
            )
            logging.debug("%s", r.stdout.decode("utf-8", errors="replace"))

        # copy the pcaps from the simulator
        self._copy_logs("sim", sim_log_dir)
        self._copy_logs("client", client_log_dir)
        self._copy_logs("server", server_log_dir)

        # Aggregate stats
        container_stats = {
            'server': self._aggregate_stats(server_stats),
            'client': self._aggregate_stats(client_stats)
        }
        
        logging.debug("Stats collected - Server: %d samples, Client: %d samples", 
                    len(server_stats), len(client_stats))

        if not expired:
            lines = output.splitlines()
            if self._is_unsupported(lines):
                status = TestResult.UNSUPPORTED
            elif any("client exited with code 0" in str(line) for line in lines):
                try:
                    testcase._container_stats = container_stats
                    status = testcase.check()
                except FileNotFoundError as e:
                    logging.error(f"testcase.check() threw FileNotFoundError: {e}")
                    status = TestResult.FAILED

        # save logs
        logging.getLogger().removeHandler(log_handler)
        log_handler.close()
        if status == TestResult.FAILED or status == TestResult.SUCCEEDED:
            log_dir = self._log_dir + "/" + server + "_" + client + "/" + str(testcase)
            if log_dir_prefix:
                log_dir += "/" + log_dir_prefix
            shutil.copytree(server_log_dir.name, log_dir + "/server")
            shutil.copytree(client_log_dir.name, log_dir + "/client")
            shutil.copytree(sim_log_dir.name, log_dir + "/sim")
            shutil.copyfile(log_file.name, log_dir + "/output.txt")
            if self._save_files and status == TestResult.FAILED:
                shutil.copytree(testcase.www_dir(), log_dir + "/www")
                try:
                    shutil.copytree(testcase.download_dir(), log_dir + "/downloads")
                except Exception as exception:
                    logging.info("Could not copy downloaded files: %s", exception)

        testcase.cleanup()
        server_log_dir.cleanup()
        client_log_dir.cleanup()
        sim_log_dir.cleanup()
        logging.debug(
            "Test: %s took %ss, status: %s",
            str(testcase),
            (datetime.now() - start_time).total_seconds(),
            str(status),
        )

        # measurements also have a value
        if hasattr(testcase, "result"):
            value = testcase.result()
        else:
            value = None

        return status, value, container_stats

    def _run_measurement(
        self, server: str, client: str, test: Callable[[], testcases.Measurement]
    ) -> MeasurementResult:
        
        if test.repetitions() > 1:
            logging.debug("Running warmup iteration...")
            warmup_result, _, warmup_stats = self._run_test(server, client, "warmup", test)
            if warmup_result != TestResult.SUCCEEDED:
                res = MeasurementResult()
                res.result = warmup_result
                res.details = ""
                res.raw_data = None
                return res

        values = []
        all_stats = []
        for i in range(0, test.repetitions()):
            result, value, container_stats = self._run_test(server, client, "%d" % (i + 1), test)
            if result != TestResult.SUCCEEDED:
                res = MeasurementResult()
                res.result = result
                res.details = ""
                res.raw_data = None
                return res
            
            # Set container stats on the test instance for this run
            test._container_stats = container_stats
            all_stats.append(container_stats)


            values.append(value)

        logging.debug(values)
        res = MeasurementResult()
        res.result = TestResult.SUCCEEDED
        
        # Handle comprehensive measurement (returns dict)
        if values and isinstance(values[0], dict):
            # Aggregate dict results across repetitions
            all_keys = set()
            for v in values:
                all_keys.update(v.keys())
            
            aggregate = {}
            for key in all_keys:
                key_values = [v[key] for v in values if key in v]
                if key_values:
                    if len(key_values) > 1:
                        aggregate[key] = {
                            'mean': statistics.mean(key_values),
                            'stdev': statistics.stdev(key_values),
                        }
                    else:
                        aggregate[key] = {
                            'mean': key_values[0],
                            'stdev': 0,
                        }
            
            # Store raw aggregated data
            res.raw_data = aggregate
            
            # Format as readable string for display
            details_parts = []
            for key, stats in sorted(aggregate.items()):
                if len(values) > 1:
                    details_parts.append(f"{key}: {stats['mean']:.2f} (±{stats['stdev']:.2f})")
                else:
                    details_parts.append(f"{key}: {stats['mean']:.2f}")
            res.details = "; ".join(details_parts)
        else:
            # Original float handling for individual measurements
            res.raw_data = {
                'mean': statistics.mean(values),
                'stdev': statistics.stdev(values) if len(values) > 1 else 0,
                'values': values,
            }
                
            if len(values) > 1:
                res.details = "{:.2f} (± {:.2f}) {}".format(  # Changed from {:.0f}
                    statistics.mean(values), 
                    statistics.stdev(values), 
                    test.unit()
                )
            else:
                res.details = "{:.2f} {}".format(values[0], test.unit())
        
        return res

    def run(self):
        """run the interop test suite and output the table"""

        nr_failed = 0
        for client, server in self._client_server_pairs:
            logging.debug(
                "Running with server %s (%s) and client %s (%s)",
                server,
                self._implementations[server]["image"],
                client,
                self._implementations[client]["image"],
            )
            if not (
                self._check_impl_is_compliant(server)
                and self._check_impl_is_compliant(client)
            ):
                logging.info("Not compliant, skipping")
                continue

            # run the test cases
            for testcase in self._tests:
                status = self._run_testcase(server, client, testcase)
                self.test_results[server][client][testcase] = status
                if status == TestResult.FAILED:
                    nr_failed += 1

            # run the measurements
            for measurement in self._measurements:
                res = self._run_measurement(server, client, measurement)
                self.measurement_results[server][client][measurement] = res

        self._postprocess_results()
        self._print_results()
        self._export_results()
        return nr_failed
