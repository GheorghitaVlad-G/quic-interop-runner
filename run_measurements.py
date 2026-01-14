#!/usr/bin/env python3
"""
Simple batch runner - execute all measurements with predefined configuration.
Edit the CONFIG section below to change test parameters.
"""

import subprocess
import sys
import re
import json
import csv
import os
import shutil
from datetime import datetime
from typing import Dict, Any, Optional

CONFIG = {
    # Basic settings
    'protocol': 'tcp',
    'client': 'tcp-client',
    'server': 'tcp-server',
    
    # Network parameters
    'delay': '0ms',
    'bandwidth': '1Gbps',
    'queue': '5000',
    
    # Loss/corruption (set to None to disable)
    'loss_rate': None,  # e.g., 3 for 3%
    'corrupt_rate': None,
    'burst_size': None,
    
    # Jitter (set to None to disable)
    'jitter_variance': None,  # e.g., '5ms'
    
    # Multipath (set all three or none)
    'delay1': None,  # e.g., '15ms'
    'delay2': None,  # e.g., '50ms'
    'probability': None,  # e.g., '0.2'
    
    # Cross traffic (set to False to disable)
    'tcp_cross_traffic': False,
    'udp_cross_traffic': False,
    'crossdatarate': None,  # e.g., '8Mbps', mandatory for UDP cross traffic
    
    # Other
    'file_size': '100MB',  # e.g., '10MB'
    'protect_tcp_acks': False, # Only for tcp
    
    # Output
    'log_dir_base': 'batch_logs',  # Base directory for logs
    'json_output': True,
    'results_dir': 'batch_results',  # Directory for summaries and CSVs
    'csv_file': 'measurements.csv',  # CSV file to append results
}

# List of measurements to run
MEASUREMENTS = [
    'handshake_time',
    'ttfb',
    'transfer_time',
    'throughput',
    'goodput',
    'retransmission_rate',
    'recovery_time',
    # 'reordering_rate',
    # 'jitter',
    'tail_latency',
    'cpu_usage',
    'memory_usage',
]

def build_command(measurement: str, log_dir: str, json_file: Optional[str] = None) -> list:
    """Build the run.py command for a measurement."""
    cmd = [
        'python3', 'run.py',
        '--protocol', CONFIG['protocol'],
        '--client', CONFIG['client'],
        '--server', CONFIG['server'],
        '-t', measurement,
        '--delay', CONFIG['delay'],
        '--bandwidth', CONFIG['bandwidth'],
        '--queue', CONFIG['queue'],
    ]
    
    # Add optional network parameters
    if CONFIG['loss_rate'] is not None:
        cmd.extend(['--loss-rate', str(CONFIG['loss_rate'])])
    
    if CONFIG['corrupt_rate'] is not None:
        cmd.extend(['--corrupt-rate', str(CONFIG['corrupt_rate'])])
    
    if CONFIG['burst_size'] is not None:
        cmd.extend(['--burst-size', str(CONFIG['burst_size'])])
    
    if CONFIG['jitter_variance'] is not None:
        cmd.extend(['--jitter-variance', CONFIG['jitter_variance']])
    
    # Multipath
    if CONFIG['delay1'] is not None:
        cmd.extend(['--delay1', CONFIG['delay1']])
    if CONFIG['delay2'] is not None:
        cmd.extend(['--delay2', CONFIG['delay2']])
    if CONFIG['probability'] is not None:
        cmd.extend(['--probability', str(CONFIG['probability'])])
    
    # Cross traffic
    if CONFIG['tcp_cross_traffic']:
        cmd.append('--tcp-cross-traffic')
    if CONFIG['udp_cross_traffic']:
        cmd.append('--udp-cross-traffic')
    if CONFIG['crossdatarate'] is not None:
        cmd.extend(['--crossdatarate', CONFIG['crossdatarate']])
    
    # File size
    if CONFIG['file_size'] is not None:
        cmd.extend(['--file-size', CONFIG['file_size']])
    
    # TCP ACK protection
    if CONFIG['protect_tcp_acks']:
        cmd.append('--protect-tcp-acks')
    
    # Log directory
    cmd.extend(['--log-dir', log_dir])
    
    # JSON output
    if json_file and CONFIG['json_output']:
        cmd.extend(['--json', json_file])
    
    return cmd

def parse_measurement_output(output: str, measurement: str) -> Optional[str]:
    """Extract measurement result from stdout."""
    lines = output.split('\n')
    for line in lines:
        if '|' in line and (CONFIG['client'] in line or CONFIG['server'] in line):
            parts = line.split('|')
            if len(parts) >= 3:
                result = parts[2].strip()
                if result and result != '':
                    return result
    
    return None

def parse_json_output(json_file: str) -> Optional[Dict[str, Any]]:
    """Parse JSON output file and extract measurement data."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
            
        if 'measurements' in data and len(data['measurements']) > 0:
            measurements = data['measurements'][0]
            if measurements:
                return measurements[0] if isinstance(measurements, list) else measurements
                
    except (FileNotFoundError, json.JSONDecodeError, KeyError, IndexError) as e:
        print(f"  Warning: Could not parse JSON output: {e}")
        
    return None

def format_measurement_result(result_data: Optional[Dict[str, Any]], text_result: Optional[str]) -> str:
    """Format measurement result for display."""
    if result_data and 'details' in result_data:
        details = result_data['details']
        
        if 'data' in result_data:
            data = result_data['data']
            if isinstance(data, dict):
                if all(isinstance(v, dict) and 'mean' in v for v in data.values()):
                    parts = []
                    for key, stats in sorted(data.items()):
                        parts.append(f"{key}: {stats['mean']:.2f} (±{stats['stdev']:.2f})")
                    return "; ".join(parts)
                elif 'mean' in data:
                    return f"{data['mean']:.2f} (±{data.get('stdev', 0):.2f})"
        
        return details
    
    if text_result:
        return text_result
    
    return "No result"

def extract_numeric_result(result_data: Optional[Dict[str, Any]]) -> Optional[float]:
    """Extract single numeric value from result data (mean value)."""
    if result_data and 'data' in result_data:
        data = result_data['data']
        if isinstance(data, dict) and 'mean' in data:
            return data['mean']
    return None

def run_measurement(measurement: str, index: int, total: int, base_log_dir: str) -> tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """Run a single measurement and return (success, result_string, json_data)."""
    print(f"\n{'='*80}")
    print(f"[{index}/{total}] Running: {measurement}")
    print(f"{'='*80}\n")
    
    log_dir = f"{base_log_dir}/{measurement}"
    json_file = f"{base_log_dir}/{measurement}_results.json" if CONFIG['json_output'] else None
    
    cmd = build_command(measurement, log_dir, json_file)
    print(f"Command: {' '.join(cmd)}\n")
    
    try:
        result = subprocess.run(
            cmd, 
            check=False,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            text_result = parse_measurement_output(result.stdout, measurement)
            json_result = parse_json_output(json_file) if json_file else None
            formatted_result = format_measurement_result(json_result, text_result)
            
            print(f"\n✓ {measurement} completed successfully")
            print(f"  Result: {formatted_result}")
            return True, formatted_result, json_result
        else:
            print(f"\n✗ {measurement} failed with return code {result.returncode}")
            error_lines = result.stdout.split('\n')[-5:]
            print(f"  Last output lines:")
            for line in error_lines:
                if line.strip():
                    print(f"    {line}")
            return False, None, None
            
    except KeyboardInterrupt:
        print(f"\n\n⚠ Interrupted by user")
        raise
    except Exception as e:
        print(f"\n✗ {measurement} failed with error: {e}")
        return False, None, None

def print_results_table(results: Dict[str, Any]):
    """Print a nicely formatted results table."""
    print(f"\n{'='*80}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*80}\n")
    
    max_name_len = max(len(m) for m in MEASUREMENTS)
    max_result_len = max(
        len(results['results'].get(m, 'FAILED')) for m in MEASUREMENTS
    )
    
    print(f"{'Measurement':<{max_name_len}}  | {'Result':<{max_result_len}} | Status")
    print(f"{'-' * max_name_len}--+-{'-' * max_result_len}-+---------")
    
    for measurement in MEASUREMENTS:
        status = '✓ PASS' if measurement in results['success'] else '✗ FAIL'
        result_str = results['results'].get(measurement, 'FAILED')
        print(f"{measurement:<{max_name_len}}  | {result_str:<{max_result_len}} | {status}")
    
    print(f"\n{'-' * 80}")
    print(f"Total: {len(MEASUREMENTS)} | Passed: {len(results['success'])} | Failed: {len(results['failed'])}")
    print(f"{'-' * 80}\n")

def append_to_csv(results: Dict[str, Any], timestamp: str, duration):
    """Append results to CSV file (create with headers if doesn't exist)."""
    results_dir = CONFIG['results_dir']
    csv_path = os.path.join(results_dir, CONFIG['csv_file'])
    
    # Ensure results directory exists
    os.makedirs(results_dir, exist_ok=True)
    
    # Check if CSV exists to determine if we need headers
    file_exists = os.path.exists(csv_path)
    
    # Prepare row data
    row = {
        # Metadata
        'timestamp': timestamp,
        'duration_seconds': duration.total_seconds(),
        
        # Input parameters (configuration)
        'protocol': CONFIG['protocol'],
        'client': CONFIG['client'],
        'server': CONFIG['server'],
        'delay': CONFIG['delay'],
        'bandwidth': CONFIG['bandwidth'],
        'queue': CONFIG['queue'],
        'loss_rate': CONFIG['loss_rate'] or '',
        'corrupt_rate': CONFIG['corrupt_rate'] or '',
        'burst_size': CONFIG['burst_size'] or '',
        'jitter_variance': CONFIG['jitter_variance'] or '',
        'delay1': CONFIG['delay1'] or '',
        'delay2': CONFIG['delay2'] or '',
        'probability': CONFIG['probability'] or '',
        'tcp_cross_traffic': CONFIG['tcp_cross_traffic'],
        'udp_cross_traffic': CONFIG['udp_cross_traffic'],
        'crossdatarate': CONFIG['crossdatarate'] or '',
        'file_size': CONFIG['file_size'] or '',
        'protect_tcp_acks': CONFIG['protect_tcp_acks'],
        
        # Output parameters (measurements)
        # Add columns for each measurement
    }
    
    # Add measurement results to row
    for measurement in MEASUREMENTS:
        json_data = results['json_data'].get(measurement)
        numeric_value = extract_numeric_result(json_data)
        
        # Add both the formatted string and numeric value
        row[f'{measurement}_result'] = results['results'].get(measurement, 'FAILED')
        row[f'{measurement}_value'] = numeric_value if numeric_value is not None else ''
        row[f'{measurement}_status'] = 'PASS' if measurement in results['success'] else 'FAIL'
    
    # Write to CSV
    with open(csv_path, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        
        # Write header if file is new
        if not file_exists:
            writer.writeheader()
        
        writer.writerow(row)
    
    print(f"Results appended to: {csv_path}")

def organize_outputs(base_log_dir: str, timestamp: str):
    """Move summaries and JSONs to results directory, cleanup logs."""
    results_dir = CONFIG['results_dir']
    run_results_dir = os.path.join(results_dir, f'run_{timestamp}')
    
    # Create run-specific directory
    os.makedirs(run_results_dir, exist_ok=True)
    
    # Move summary file
    summary_src = os.path.join(base_log_dir, 'summary.txt')
    if os.path.exists(summary_src):
        shutil.move(summary_src, os.path.join(run_results_dir, 'summary.txt'))
    
    # Move all JSON files
    for measurement in MEASUREMENTS:
        json_src = os.path.join(base_log_dir, f'{measurement}_results.json')
        if os.path.exists(json_src):
            shutil.move(json_src, os.path.join(run_results_dir, f'{measurement}_results.json'))
    
    # Optional: Remove entire log directory to save space
    # Uncomment if you don't need detailed logs
    # shutil.rmtree(base_log_dir)
    
    print(f"Summaries and JSONs moved to: {run_results_dir}")
    print(f"Detailed logs remain in: {base_log_dir}")

def main():
    print(f"\n{'='*80}")
    print(f"Batch Measurement Runner")
    print(f"{'='*80}")
    print(f"\nConfiguration:")
    print(f"  Protocol: {CONFIG['protocol']}")
    print(f"  Client: {CONFIG['client']}")
    print(f"  Server: {CONFIG['server']}")
    print(f"  Network: {CONFIG['delay']} delay, {CONFIG['bandwidth']} bandwidth, {CONFIG['queue']} queue")
    if CONFIG['loss_rate']:
        print(f"  Loss rate: {CONFIG['loss_rate']}%")
    if CONFIG['jitter_variance']:
        print(f"  Jitter: {CONFIG['jitter_variance']}")
    if CONFIG['delay1'] and CONFIG['delay2']:
        print(f"  Multipath Reordering: {CONFIG['delay1']}/{CONFIG['delay2']} (p={CONFIG['probability']})")
    
    print(f"\nMeasurements to run ({len(MEASUREMENTS)}):")
    for m in MEASUREMENTS:
        print(f"  - {m}")
    
    print(f"\n{'='*80}\n")
    
    response = input("Continue? [Y/n]: ")
    if response.lower() == 'n':
        print("Aborted.")
        return 1
    
    # Setup logging directory
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_log_dir = f"{CONFIG['log_dir_base']}_{timestamp}"
    
    start_time = datetime.now()
    results = {
        'success': [],
        'failed': [],
        'results': {},  # Store formatted result strings
        'json_data': {}  # Store raw JSON data
    }
    
    try:
        for i, measurement in enumerate(MEASUREMENTS, 1):
            success, result_str, json_data = run_measurement(measurement, i, len(MEASUREMENTS), base_log_dir)
            if success:
                results['success'].append(measurement)
                results['results'][measurement] = result_str or 'PASS'
                results['json_data'][measurement] = json_data
            else:
                results['failed'].append(measurement)
                results['results'][measurement] = 'FAILED'
                results['json_data'][measurement] = None
    
    except KeyboardInterrupt:
        print(f"\n\n⚠ Batch run interrupted by user\n")
        return 1
    
    # Calculate duration
    duration = datetime.now() - start_time
    
    # Print results table
    print_results_table(results)
    
    print(f"\n{'='*80}")
    print(f"TIMING")
    print(f"{'='*80}")
    print(f"Duration: {duration}")
    print(f"Average per measurement: {duration / len(MEASUREMENTS)}")
    print(f"\n{'='*80}\n")
    
    if results['failed']:
        print(f"Failed measurements:")
        for m in results['failed']:
            print(f"  ✗ {m}")
        print()
    
    # Save summary to file
    summary_file = f"{base_log_dir}/summary.txt"
    try:
        with open(summary_file, 'w') as f:
            f.write(f"Batch Measurement Run Summary\n")
            f.write(f"=" * 80 + "\n\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Duration: {duration}\n")
            f.write(f"Configuration: {CONFIG}\n\n")
            f.write(f"Results:\n")
            f.write(f"-" * 80 + "\n")
            for measurement in MEASUREMENTS:
                status = 'PASS' if measurement in results['success'] else 'FAIL'
                result_str = results['results'].get(measurement, 'FAILED')
                f.write(f"{measurement}: {status} - {result_str}\n")
            f.write(f"\nSummary: {len(results['success'])}/{len(MEASUREMENTS)} passed\n")
        print(f"Summary saved to: {summary_file}\n")
    except Exception as e:
        print(f"Warning: Could not save summary file: {e}\n")
    
    # Append to CSV
    try:
        append_to_csv(results, timestamp, duration)
    except Exception as e:
        print(f"Warning: Could not append to CSV: {e}\n")
    
    # Organize outputs
    try:
        organize_outputs(base_log_dir, timestamp)
    except Exception as e:
        print(f"Warning: Could not organize outputs: {e}\n")
    
    return 0 if not results['failed'] else 1


if __name__ == '__main__':
    sys.exit(main())