"""
M365 PCI Kuwait Scanner - Card Data Detection Module

This module provides advanced card data detection capabilities for Microsoft 365
environments with specialized patterns for Kuwait financial sector.

Author: Ali AlEnezi
Email: site@hotmail.com
LinkedIn: linkedin.com/in/alenizi
"""

import re
import logging
import asyncio
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import luhn  # For credit card validation

logger = logging.getLogger(__name__)

class CardDataDetector:
    """Advanced card data detection engine for Microsoft 365 environments."""
    
    def __init__(self, config: Dict):
        """Initialize the card data detector with configuration."""
        self.config = config
        self.scan_results = []
        
        # Initialize card patterns
        self._initialize_card_patterns()
        self._initialize_kuwait_patterns()
        self._initialize_sensitive_patterns()
    
    def _initialize_card_patterns(self):
        """Initialize credit card detection patterns."""
        self.card_patterns = {
            'visa': {
                'pattern': r'\b4[0-9]{12}(?:[0-9]{3})?\b',
                'length': [13, 16, 19],
                'issuer': 'Visa',
                'priority': 'HIGH'
            },
            'mastercard': {
                'pattern': r'\b5[1-5][0-9]{14}\b',
                'length': [16],
                'issuer': 'MasterCard',
                'priority': 'HIGH'
            },
            'amex': {
                'pattern': r'\b3[47][0-9]{13}\b',
                'length': [15],
                'issuer': 'American Express',
                'priority': 'HIGH'
            },
            'discover': {
                'pattern': r'\b6(?:011|5[0-9]{2})[0-9]{12}\b',
                'length': [16],
                'issuer': 'Discover',
                'priority': 'MEDIUM'
            },
            'diners': {
                'pattern': r'\b3[0689][0-9]{11}\b',
                'length': [14],
                'issuer': 'Diners Club',
                'priority': 'MEDIUM'
            },
            'jcb': {
                'pattern': r'\b35[0-9]{14}\b',
                'length': [16],
                'issuer': 'JCB',
                'priority': 'MEDIUM'
            }
        }
        
        # CVV/CVC patterns
        self.cvv_patterns = {
            'cvv': r'\b[0-9]{3,4}\b',
            'cvc': r'\b[0-9]{3,4}\b',
            'cvv2': r'\b[0-9]{3,4}\b',
            'cvc2': r'\b[0-9]{3,4}\b'
        }
        
        # Expiration date patterns
        self.expiry_patterns = {
            'mm_yy': r'\b(0[1-9]|1[0-2])[/\-](2[0-9]|[0-9]{2})\b',
            'mm_yyyy': r'\b(0[1-9]|1[0-2])[/\-](20[2-9][0-9])\b',
            'expires': r'exp[iry]*[:\s]*\b(0[1-9]|1[0-2])[/\-](2[0-9]|[0-9]{2})\b'
        }
    
    def _initialize_kuwait_patterns(self):
        """Initialize Kuwait-specific card and banking patterns."""
        self.kuwait_patterns = {
            'knet': {
                'pattern': r'\b(627780|440621)[0-9]{10}\b',
                'issuer': 'K-Net',
                'country': 'Kuwait',
                'priority': 'CRITICAL'
            },
            'cbk_bin': {
                'pattern': r'\b(409167|409168|409169|409170)[0-9]{10}\b',
                'issuer': 'CBK Licensed Bank',
                'country': 'Kuwait',
                'priority': 'CRITICAL'
            },
            'kuwait_visa': {
                'pattern': r'\b4(09167|09168|09169|09170|27780)[0-9]{11}\b',
                'issuer': 'Kuwait Visa',
                'country': 'Kuwait',
                'priority': 'CRITICAL'
            },
            'kuwait_mastercard': {
                'pattern': r'\b5(27780|40962)[0-9]{11}\b',
                'issuer': 'Kuwait MasterCard',
                'country': 'Kuwait',
                'priority': 'CRITICAL'
            },
            'kuwait_iban': {
                'pattern': r'\bKW[0-9]{2}[A-Z]{4}[0-9A-Z]{22}\b',
                'issuer': 'Kuwait IBAN',
                'country': 'Kuwait',
                'priority': 'HIGH'
            }
        }
    
    def _initialize_sensitive_patterns(self):
        """Initialize sensitive data patterns related to card processing."""
        self.sensitive_patterns = {
            'track_data': {
                'track1': r'%[A-Z][0-9]{1,19}\^[A-Z\s]{2,26}\^[0-9]{4}[0-9]*\?',
                'track2': r';[0-9]{1,19}=[0-9]{4}[0-9]*\?',
                'track3': r';[0-9]{1,104}\?'
            },
            'pin_data': {
                'pin_block': r'\b[0-9A-F]{16}\b',
                'pin_verification': r'PIN[:\s]*[0-9]{4,8}\b'
            },
            'cardholder_data': {
                'name_on_card': r'(?i)(card\s*holder|name\s*on\s*card)[:\s]*([A-Z\s]{2,50})',
                'billing_address': r'(?i)(billing\s*address|card\s*address)[:\s]*([A-Z0-9\s,.-]{10,100})'
            }
        }
    
    async def scan_all_locations(self, m365_connector, sensitive_locations: List[Dict]) -> Dict:
        """Scan all discovered locations for card data."""
        logger.info(f"Starting card data scan across {len(sensitive_locations)} locations")
        
        scan_results = {
            'summary': {
                'locations_scanned': 0,
                'files_scanned': 0,
                'card_data_found': 0,
                'critical_findings': 0,
                'high_risk_locations': []
            },
            'findings': [],
            'critical_findings': [],
            'patterns_detected': {},
            'risk_assessment': {}
        }
        
        for location in sensitive_locations:
            try:
                location_results = await self._scan_location(m365_connector, location)
                scan_results['findings'].extend(location_results['findings'])
                
                # Update summary statistics
                scan_results['summary']['locations_scanned'] += 1
                scan_results['summary']['files_scanned'] += location_results['files_scanned']
                
                # Check for critical findings
                critical_findings = [f for f in location_results['findings'] if f['severity'] == 'CRITICAL']
                if critical_findings:
                    scan_results['critical_findings'].extend(critical_findings)
                    scan_results['summary']['high_risk_locations'].append(location['path'])
                
                logger.debug(f"Scanned location: {location['path']}")
                
            except Exception as e:
                logger.error(f"Error scanning location {location['path']}: {e}")
                continue
        
        # Calculate final statistics
        scan_results['summary']['card_data_found'] = len(scan_results['findings'])
        scan_results['summary']['critical_findings'] = len(scan_results['critical_findings'])
        
        # Perform risk assessment
        scan_results['risk_assessment'] = self._assess_card_data_risk(scan_results)
        
        logger.info(f"Card data scan completed. Found {scan_results['summary']['card_data_found']} potential card data instances")
        
        return scan_results
    
    async def _scan_location(self, m365_connector, location: Dict) -> Dict:
        """Scan a specific location for card data."""
        location_results = {
            'location': location['path'],
            'files_scanned': 0,
            'findings': []
        }
        
        # Determine scan method based on location type
        if location['type'] == 'sharepoint_site':
            files = await m365_connector.get_sharepoint_files(location['path'])
        elif location['type'] == 'onedrive':
            files = await m365_connector.get_onedrive_files(location['path'])
        elif location['type'] == 'exchange_mailbox':
            files = await m365_connector.get_email_attachments(location['path'])
        elif location['type'] == 'teams_files':
            files = await m365_connector.get_teams_files(location['path'])
        else:
            logger.warning(f"Unknown location type: {location['type']}")
            return location_results
        
        # Scan each file for card data
        for file_info in files:
            try:
                if self._should_scan_file(file_info):
                    file_content = await m365_connector.get_file_content(file_info)
                    file_findings = await self._scan_file_content(file_content, file_info, location)
                    location_results['findings'].extend(file_findings)
                    location_results['files_scanned'] += 1
                    
            except Exception as e:
                logger.debug(f"Error scanning file {file_info.get('name', 'unknown')}: {e}")
                continue
        
        return location_results
    
    def _should_scan_file(self, file_info: Dict) -> bool:
        """Determine if a file should be scanned for card data."""
        # File size limits
        max_size = self.config.get('scan_settings', {}).get('max_file_size_mb', 100) * 1024 * 1024
        if file_info.get('size', 0) > max_size:
            return False
        
        # File type filters
        scannable_extensions = {
            '.txt', '.csv', '.xlsx', '.xls', '.docx', '.doc', '.pdf', 
            '.pptx', '.ppt', '.html', '.htm', '.xml', '.json'
        }
        
        file_name = file_info.get('name', '').lower()
        file_extension = '.' + file_name.split('.')[-1] if '.' in file_name else ''
        
        return file_extension in scannable_extensions
    
    async def _scan_file_content(self, content: str, file_info: Dict, location: Dict) -> List[Dict]:
        """Scan file content for card data patterns."""
        findings = []
        
        if not content:
            return findings
        
        # Scan for credit card numbers
        card_findings = self._detect_card_numbers(content, file_info, location)
        findings.extend(card_findings)
        
        # Scan for Kuwait-specific patterns
        kuwait_findings = self._detect_kuwait_patterns(content, file_info, location)
        findings.extend(kuwait_findings)
        
        # Scan for track data
        track_findings = self._detect_track_data(content, file_info, location)
        findings.extend(track_findings)
        
        # Scan for CVV/CVC codes near card numbers
        if card_findings:  # Only scan for CVV if card numbers found
            cvv_findings = self._detect_cvv_near_cards(content, file_info, location)
            findings.extend(cvv_findings)
        
        # Scan for cardholder data
        cardholder_findings = self._detect_cardholder_data(content, file_info, location)
        findings.extend(cardholder_findings)
        
        return findings
    
    def _detect_card_numbers(self, content: str, file_info: Dict, location: Dict) -> List[Dict]:
        """Detect credit card numbers in content."""
        findings = []
        
        for card_type, pattern_info in self.card_patterns.items():
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                card_number = match.group().replace(' ', '').replace('-', '')
                
                # Validate using Luhn algorithm
                if self._validate_card_number(card_number):
                    # Check if it's a test card number
                    if not self._is_test_card(card_number):
                        finding = {
                            'type': 'credit_card_number',
                            'card_type': card_type,
                            'issuer': pattern_info['issuer'],
                            'severity': 'CRITICAL',
                            'location': location['path'],
                            'file': file_info.get('name', 'unknown'),
                            'file_id': file_info.get('id'),
                            'masked_number': self._mask_card_number(card_number),
                            'position': match.span(),
                            'context': self._get_context(content, match.span()),
                            'pci_requirement': 'REQ-3.4',
                            'description': f'{pattern_info["issuer"]} card number detected',
                            'remediation': 'Remove or encrypt card data immediately',
                            'risk_factors': self._assess_card_risk_factors(content, match.span())
                        }
                        findings.append(finding)
        
        return findings
    
    def _detect_kuwait_patterns(self, content: str, file_info: Dict, location: Dict) -> List[Dict]:
        """Detect Kuwait-specific card and banking patterns."""
        findings = []
        
        for pattern_name, pattern_info in self.kuwait_patterns.items():
            pattern = pattern_info['pattern']
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                finding = {
                    'type': 'kuwait_banking_data',
                    'pattern_type': pattern_name,
                    'issuer': pattern_info['issuer'],
                    'severity': pattern_info['priority'],
                    'location': location['path'],
                    'file': file_info.get('name', 'unknown'),
                    'file_id': file_info.get('id'),
                    'masked_data': self._mask_sensitive_data(match.group()),
                    'position': match.span(),
                    'context': self._get_context(content, match.span()),
                    'cbk_regulation': 'CBK-CS-001',
                    'description': f'Kuwait {pattern_info["issuer"]} data detected',
                    'remediation': 'Secure according to CBK cybersecurity framework',
                    'country_risk': True
                }
                findings.append(finding)
        
        return findings
    
    def _detect_track_data(self, content: str, file_info: Dict, location: Dict) -> List[Dict]:
        """Detect magnetic stripe track data."""
        findings = []
        
        for track_type, pattern in self.sensitive_patterns['track_data'].items():
            matches = re.finditer(pattern, content)
            
            for match in matches:
                finding = {
                    'type': 'track_data',
                    'track_type': track_type,
                    'severity': 'CRITICAL',
                    'location': location['path'],
                    'file': file_info.get('name', 'unknown'),
                    'file_id': file_info.get('id'),
                    'position': match.span(),
                    'context': '[TRACK DATA DETECTED - CONTENT HIDDEN]',
                    'pci_requirement': 'REQ-3.2',
                    'description': f'Magnetic stripe {track_type} data detected',
                    'remediation': 'Immediately remove track data - storage prohibited',
                    'prohibited_data': True
                }
                findings.append(finding)
        
        return findings
    
    def _detect_cvv_near_cards(self, content: str, file_info: Dict, location: Dict) -> List[Dict]:
        """Detect CVV/CVC codes near card numbers."""
        findings = []
        
        # Look for CVV patterns within 100 characters of card numbers
        card_positions = []
        for card_type, pattern_info in self.card_patterns.items():
            matches = re.finditer(pattern_info['pattern'], content)
            card_positions.extend([match.span() for match in matches])
        
        if not card_positions:
            return findings
        
        for cvv_type, pattern in self.cvv_patterns.items():
            matches = re.finditer(pattern, content)
            
            for match in matches:
                cvv_pos = match.span()
                
                # Check if CVV is near any card number
                for card_pos in card_positions:
                    distance = min(abs(cvv_pos[0] - card_pos[1]), abs(card_pos[0] - cvv_pos[1]))
                    
                    if distance <= 100:  # Within 100 characters
                        finding = {
                            'type': 'cvv_near_card',
                            'cvv_type': cvv_type,
                            'severity': 'CRITICAL',
                            'location': location['path'],
                            'file': file_info.get('name', 'unknown'),
                            'file_id': file_info.get('id'),
                            'position': cvv_pos,
                            'context': '[CVV DATA DETECTED - CONTENT HIDDEN]',
                            'pci_requirement': 'REQ-3.2.1',
                            'description': f'{cvv_type.upper()} detected near card number',
                            'remediation': 'Remove CVV data - storage prohibited after authorization',
                            'prohibited_data': True
                        }
                        findings.append(finding)
                        break  # Only report once per CVV
        
        return findings
    
    def _detect_cardholder_data(self, content: str, file_info: Dict, location: Dict) -> List[Dict]:
        """Detect cardholder names and related data."""
        findings = []
        
        for data_type, pattern in self.sensitive_patterns['cardholder_data'].items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                finding = {
                    'type': 'cardholder_data',
                    'data_type': data_type,
                    'severity': 'HIGH',
                    'location': location['path'],
                    'file': file_info.get('name', 'unknown'),
                    'file_id': file_info.get('id'),
                    'position': match.span(),
                    'context': self._get_context(content, match.span(), mask_sensitive=True),
                    'pci_requirement': 'REQ-3.4',
                    'description': f'Cardholder {data_type.replace("_", " ")} detected',
                    'remediation': 'Encrypt or remove cardholder data'
                }
                findings.append(finding)
        
        return findings
    
    def _validate_card_number(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        try:
            return luhn.verify(card_number)
        except:
            return False
    
    def _is_test_card(self, card_number: str) -> bool:
        """Check if the card number is a known test card."""
        test_patterns = [
            '4111111111111111',  # Visa test
            '4000000000000002',  # Visa test
            '5555555555554444',  # MasterCard test
            '5105105105105100',  # MasterCard test
            '378282246310005',   # Amex test
            '371449635398431',   # Amex test
        ]
        return card_number in test_patterns
    
    def _mask_card_number(self, card_number: str) -> str:
        """Mask credit card number for logging/reporting."""
        if len(card_number) < 8:
            return '*' * len(card_number)
        return card_number[:4] + '*' * (len(card_number) - 8) + card_number[-4:]
    
    def _mask_sensitive_data(self, data: str) -> str:
        """Mask sensitive data for logging/reporting."""
        if len(data) < 8:
            return '*' * len(data)
        return data[:2] + '*' * (len(data) - 4) + data[-2:]
    
    def _get_context(self, content: str, position: Tuple[int, int], 
                     context_size: int = 50, mask_sensitive: bool = False) -> str:
        """Get context around a detected pattern."""
        start, end = position
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        
        context = content[context_start:context_end]
        
        if mask_sensitive:
            # Mask potential sensitive data in context
            context = re.sub(r'\b[0-9]{13,19}\b', '***CARD***', context)
            context = re.sub(r'\b[0-9]{3,4}\b', '***CVV***', context)
        
        return context.strip()
    
    def _assess_card_risk_factors(self, content: str, position: Tuple[int, int]) -> List[str]:
        """Assess risk factors for detected card data."""
        risk_factors = []
        
        # Check for nearby sensitive data
        context = self._get_context(content, position, 200)
        
        if re.search(r'\b[0-9]{3,4}\b', context):
            risk_factors.append('CVV_NEARBY')
        
        if re.search(r'\b(0[1-9]|1[0-2])[/\-](2[0-9]|[0-9]{2})\b', context):
            risk_factors.append('EXPIRY_DATE_NEARBY')
        
        if re.search(r'(?i)(password|pin|secret)', context):
            risk_factors.append('AUTH_DATA_NEARBY')
        
        if re.search(r'(?i)(ssn|social|security)', context):
            risk_factors.append('SSN_NEARBY')
        
        return risk_factors
    
    def _assess_card_data_risk(self, scan_results: Dict) -> Dict:
        """Assess overall risk from card data findings."""
        total_findings = len(scan_results['findings'])
        critical_findings = len(scan_results['critical_findings'])
        
        # Risk score calculation (0-100)
        base_score = min(100, critical_findings * 25)
        
        # Risk factors
        risk_factors = []
        if critical_findings > 0:
            risk_factors.append('CARD_DATA_EXPOSED')
        
        track_data_count = len([f for f in scan_results['findings'] if f['type'] == 'track_data'])
        if track_data_count > 0:
            risk_factors.append('PROHIBITED_DATA_STORED')
            base_score += track_data_count * 10
        
        cvv_count = len([f for f in scan_results['findings'] if f['type'] == 'cvv_near_card'])
        if cvv_count > 0:
            risk_factors.append('CVV_STORAGE_VIOLATION')
            base_score += cvv_count * 15
        
        kuwait_data_count = len([f for f in scan_results['findings'] if f['type'] == 'kuwait_banking_data'])
        if kuwait_data_count > 0:
            risk_factors.append('KUWAIT_REGULATORY_VIOLATION')
            base_score += kuwait_data_count * 5
        
        # Cap at 100
        risk_score = min(100, base_score)
        
        # Risk level
        if risk_score >= 80:
            risk_level = 'CRITICAL'
        elif risk_score >= 60:
            risk_level = 'HIGH'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
        elif risk_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'recommendations': self._generate_card_data_recommendations(scan_results, risk_factors)
        }
    
    def _generate_card_data_recommendations(self, scan_results: Dict, risk_factors: List[str]) -> List[str]:
        """Generate recommendations based on card data findings."""
        recommendations = []
        
        if 'CARD_DATA_EXPOSED' in risk_factors:
            recommendations.append('Immediately secure or remove all exposed card data')
            recommendations.append('Implement Microsoft Purview DLP policies for card data')
            recommendations.append('Review access controls for locations containing card data')
        
        if 'PROHIBITED_DATA_STORED' in risk_factors:
            recommendations.append('URGENT: Remove all track data - storage is prohibited by PCI DSS')
            recommendations.append('Investigate how track data was stored and prevent future occurrences')
        
        if 'CVV_STORAGE_VIOLATION' in risk_factors:
            recommendations.append('Remove all stored CVV/CVC codes immediately')
            recommendations.append('Update payment processes to prevent CVV storage')
        
        if 'KUWAIT_REGULATORY_VIOLATION' in risk_factors:
            recommendations.append('Secure Kuwait banking data according to CBK framework')
            recommendations.append('Review data handling procedures for regulatory compliance')
        
        # General recommendations
        if scan_results['summary']['card_data_found'] > 0:
            recommendations.extend([
                'Implement automated card data discovery and monitoring',
                'Train staff on PCI DSS data handling requirements',
                'Consider data tokenization for legitimate business needs',
                'Schedule regular PCI compliance scans'
            ])
        
        return recommendations