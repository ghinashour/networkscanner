"""
Dataset builder for creating labeled training data for ML models.
Generates CSV datasets with features and labels for device classification.
"""

import csv
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
import logging

# Setup logger
logger = logging.getLogger(__name__)

class DatasetBuilder:
    """Builds labeled datasets for machine learning."""
    
    def __init__(self, data_dir: str = "data/datasets"):
        """Initialize the dataset builder."""
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.datasets = {}
        logger.info(f"Dataset builder initialized (data_dir: {self.data_dir})")
    
    def create_device_dataset(self, scan_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Create a dataset from scanned devices.
        
        Args:
            scan_data: List of device scan results
        
        Returns:
            List of device features
        """
        logger.info(f"Creating device dataset from {len(scan_data)} devices")
        
        dataset = []
        
        for device in scan_data:
            # Extract features
            services = device.get('services', [])
            open_ports = [s.get('port') for s in services if s.get('state') == 'open' and s.get('port')]
            
            # Calculate features
            features = {
                'host_id': device.get('id', len(dataset) + 1),
                'ip_address': device.get('ip_address', ''),
                'mac_address': device.get('mac_address', ''),
                'hostname': device.get('hostname', ''),
                'os_name': device.get('os_name', ''),
                'os_family': device.get('os_family', ''),
                'open_port_count': len(open_ports),
                'service_count': len(services),
                'has_ssh': 1 if 22 in open_ports else 0,
                'has_http': 1 if 80 in open_ports else 0,
                'has_https': 1 if 443 in open_ports else 0,
                'has_telnet': 1 if 23 in open_ports else 0,
                'has_ftp': 1 if 21 in open_ports else 0,
                'has_smtp': 1 if 25 in open_ports else 0,
                'has_rdp': 1 if 3389 in open_ports else 0,
                'has_mysql': 1 if 3306 in open_ports else 0,
                'has_postgres': 1 if 5432 in open_ports else 0,
                'has_mongodb': 1 if 27017 in open_ports else 0,
                'has_redis': 1 if 6379 in open_ports else 0,
                'device_type': device.get('device_type', 'unknown'),
                'classification_confidence': device.get('confidence', 0.0)
            }
            
            dataset.append(features)
        
        logger.info(f"Created dataset with {len(dataset)} devices")
        return dataset
    
    def add_labels_from_classifications(self, dataset: List[Dict[str, Any]], 
                                       classifications: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Add labels based on device classifications.
        
        Args:
            dataset: List of device features
            classifications: Dictionary mapping IP to device_type
        
        Returns:
            Dataset with added labels
        """
        logger.info(f"Adding labels from {len(classifications)} classifications")
        
        for item in dataset:
            ip = item.get('ip_address')
            if ip in classifications:
                item['device_type'] = classifications[ip]
                item['classification_confidence'] = 1.0
        
        labeled = sum(1 for item in dataset if item.get('device_type') != 'unknown')
        logger.info(f"Added labels: {labeled}/{len(dataset)} devices labeled")
        
        return dataset
    
    def manual_label_dataset(self, dataset: List[Dict[str, Any]], 
                            label_mapping: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Manually label devices in the dataset.
        
        Args:
            dataset: List of device features
            label_mapping: Dictionary mapping ip_address to device_type
        
        Returns:
            Dataset with manual labels applied
        """
        logger.info(f"Applying manual labels for {len(label_mapping)} devices")
        
        for item in dataset:
            ip = item.get('ip_address')
            if ip in label_mapping:
                item['device_type'] = label_mapping[ip]
                item['classification_confidence'] = 1.0
        
        labeled = sum(1 for item in dataset if item.get('device_type') != 'unknown')
        logger.info(f"Manual labeling complete: {labeled}/{len(dataset)} devices labeled")
        
        return dataset
    
    def save_dataset(self, dataset: List[Dict[str, Any]], name: str, 
                    include_labels: bool = True) -> str:
        """
        Save dataset to CSV file.
        
        Args:
            dataset: List of device features
            name: Dataset name
            include_labels: Whether to include label column
        
        Returns:
            Path to saved file
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{name}_{timestamp}.csv"
        filepath = self.data_dir / filename
        
        if not dataset:
            logger.warning("Dataset is empty, nothing to save")
            return str(filepath)
        
        # Get all field names
        fieldnames = list(dataset[0].keys())
        
        # Remove label columns if not included
        if not include_labels:
            fieldnames = [f for f in fieldnames if f not in ['device_type', 'classification_confidence']]
        
        # Write to CSV
        try:
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for row in dataset:
                    # Filter rows if labels not included
                    if not include_labels:
                        row = {k: v for k, v in row.items() if k in fieldnames}
                    writer.writerow(row)
            
            logger.info(f"Dataset saved to: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Failed to save dataset: {str(e)}")
            raise
    
    def load_dataset(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Load a saved dataset.
        
        Args:
            filepath: Path to CSV file
        
        Returns:
            Loaded dataset as list of dicts
        """
        dataset = []
        
        try:
            with open(filepath, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    # Convert numeric values
                    for key, value in row.items():
                        if value.isdigit():
                            row[key] = int(value)
                        elif value.replace('.', '').isdigit():
                            row[key] = float(value)
                    dataset.append(row)
            
            logger.info(f"Loaded dataset from {filepath}: {len(dataset)} rows")
            return dataset
            
        except Exception as e:
            logger.error(f"Failed to load dataset: {str(e)}")
            return []
    
    def analyze_dataset(self, dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze the dataset and generate statistics.
        
        Args:
            dataset: List of device features
        
        Returns:
            Statistics about the dataset
        """
        if not dataset:
            return {'error': 'Dataset is empty'}
        
        stats = {
            'total_rows': len(dataset),
            'total_features': len(dataset[0].keys()),
            'feature_names': list(dataset[0].keys()),
            'labeled_count': 0,
            'unlabeled_count': 0,
            'device_types': {},
            'numeric_stats': {}
        }
        
        # Count labels
        for item in dataset:
            device_type = item.get('device_type', 'unknown')
            if device_type and device_type != 'unknown':
                stats['labeled_count'] += 1
                stats['device_types'][device_type] = stats['device_types'].get(device_type, 0) + 1
            else:
                stats['unlabeled_count'] += 1
        
        # Calculate numeric statistics
        numeric_fields = ['open_port_count', 'service_count', 'classification_confidence']
        for field in numeric_fields:
            if field in dataset[0]:
                values = [item.get(field, 0) for item in dataset if isinstance(item.get(field), (int, float))]
                if values:
                    stats['numeric_stats'][field] = {
                        'mean': sum(values) / len(values),
                        'min': min(values),
                        'max': max(values),
                        'count': len(values)
                    }
        
        return stats
    
    def create_feature_matrix(self, dataset: List[Dict[str, Any]]) -> Tuple[List[List[float]], List[str], List[str]]:
        """
        Create feature matrix and labels for ML.
        
        Args:
            dataset: List of device features
        
        Returns:
            Tuple of (features, labels, feature_names)
        """
        if not dataset:
            return [], [], []
        
        # Define feature columns (exclude non-feature fields)
        exclude_fields = ['host_id', 'ip_address', 'mac_address', 'hostname', 
                         'os_name', 'os_family', 'device_type', 'classification_confidence']
        
        feature_names = [f for f in dataset[0].keys() if f not in exclude_fields]
        
        # Build feature matrix
        features = []
        labels = []
        
        for item in dataset:
            feature_row = [float(item.get(f, 0)) for f in feature_names]
            features.append(feature_row)
            labels.append(item.get('device_type', 'unknown'))
        
        logger.info(f"Created feature matrix: {len(features)} rows, {len(feature_names)} features")
        return features, labels, feature_names
    
    def generate_sample_dataset(self) -> List[Dict[str, Any]]:
        """
        Generate a sample dataset with known device types for testing.
        
        Returns:
            Sample dataset
        """
        logger.info("Generating sample dataset...")
        
        sample_data = [
            # Router examples
            {
                'ip_address': '192.168.1.1',
                'open_port_count': 6,
                'service_count': 5,
                'has_ssh': 1,
                'has_http': 1,
                'has_https': 1,
                'has_telnet': 0,
                'has_ftp': 0,
                'has_smtp': 0,
                'has_rdp': 0,
                'has_mysql': 0,
                'has_postgres': 0,
                'has_mongodb': 0,
                'has_redis': 0,
                'device_type': 'router',
                'classification_confidence': 1.0
            },
            # Server examples
            {
                'ip_address': '192.168.1.10',
                'open_port_count': 10,
                'service_count': 8,
                'has_ssh': 1,
                'has_http': 1,
                'has_https': 1,
                'has_telnet': 0,
                'has_ftp': 1,
                'has_smtp': 1,
                'has_rdp': 0,
                'has_mysql': 1,
                'has_postgres': 0,
                'has_mongodb': 0,
                'has_redis': 0,
                'device_type': 'server',
                'classification_confidence': 1.0
            },
            # Workstation examples
            {
                'ip_address': '192.168.1.20',
                'open_port_count': 4,
                'service_count': 3,
                'has_ssh': 1,
                'has_http': 1,
                'has_https': 0,
                'has_telnet': 0,
                'has_ftp': 0,
                'has_smtp': 0,
                'has_rdp': 1,
                'has_mysql': 0,
                'has_postgres': 0,
                'has_mongodb': 0,
                'has_redis': 0,
                'device_type': 'workstation',
                'classification_confidence': 1.0
            },
            # IoT examples
            {
                'ip_address': '192.168.1.100',
                'open_port_count': 2,
                'service_count': 1,
                'has_ssh': 0,
                'has_http': 1,
                'has_https': 0,
                'has_telnet': 1,
                'has_ftp': 0,
                'has_smtp': 0,
                'has_rdp': 0,
                'has_mysql': 0,
                'has_postgres': 0,
                'has_mongodb': 0,
                'has_redis': 0,
                'device_type': 'iot',
                'classification_confidence': 1.0
            }
        ]
        
        # Add host_ids
        for idx, item in enumerate(sample_data, 1):
            item['host_id'] = idx
        
        logger.info(f"Generated sample dataset with {len(sample_data)} devices")
        return sample_data
    
    def generate_report(self, dataset: List[Dict[str, Any]]) -> str:
        """
        Generate an exploratory data analysis report.
        
        Args:
            dataset: List of device features
        
        Returns:
            Report as string
        """
        if not dataset:
            return "Dataset is empty"
        
        report = []
        report.append("=" * 60)
        report.append("DEVICE DATASET EXPLORATORY REPORT")
        report.append("=" * 60)
        
        # Basic statistics
        report.append(f"\nTotal Devices: {len(dataset)}")
        report.append(f"Total Features: {len(dataset[0].keys())}")
        
        # Device type distribution
        device_types = {}
        for item in dataset:
            dt = item.get('device_type', 'unknown')
            device_types[dt] = device_types.get(dt, 0) + 1
        
        report.append("\nDevice Type Distribution:")
        for dt, count in device_types.items():
            percentage = (count / len(dataset)) * 100
            report.append(f"  {dt}: {count} ({percentage:.1f}%)")
        
        # Feature statistics
        report.append("\nFeature Statistics:")
        numeric_fields = ['open_port_count', 'service_count']
        for field in numeric_fields:
            values = [item.get(field, 0) for item in dataset if isinstance(item.get(field), (int, float))]
            if values:
                report.append(f"\n{field}:")
                report.append(f"  Mean: {sum(values) / len(values):.3f}")
                report.append(f"  Min: {min(values)}")
                report.append(f"  Max: {max(values)}")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)