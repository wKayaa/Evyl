"""
Credential Validator for Evyl Framework

Validates discovered credentials against their respective services.
"""

import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from utils.logger import Logger
from validators.aws import AWSValidator
from validators.email import EmailValidator
from validators.sms import SMSValidator
from validators.smtp import SMTPValidator
from validators.database import DatabaseValidator

@dataclass
class ValidationResult:
    """Result from credential validation"""
    credential_type: str
    credential_value: str
    status: str  # 'valid', 'invalid', 'error'
    details: Dict[str, Any]
    error: Optional[str] = None

class Validator:
    """Main credential validator"""
    
    def __init__(self):
        self.logger = Logger()
        
        # Initialize validators
        self.validators = {
            'aws': AWSValidator(),
            'email': EmailValidator(),
            'sms': SMSValidator(),
            'smtp': SMTPValidator(),
            'database': DatabaseValidator()
        }
    
    async def validate_all(self, credentials: List[Dict[str, Any]], progress=None) -> List[ValidationResult]:
        """Validate all credentials"""
        results = []
        
        for cred in credentials:
            try:
                result = await self._validate_credential(cred)
                results.append(result)
                
                # Log result
                self.logger.validation_result(cred['type'], result.status)
                
                # Update progress
                if progress:
                    progress.update_network_stats(len(results))
                    
            except Exception as e:
                self.logger.error(f"Validation failed for {cred['type']}: {e}")
                results.append(ValidationResult(
                    credential_type=cred['type'],
                    credential_value=cred['value'],
                    status='error',
                    details={},
                    error=str(e)
                ))
        
        return results
    
    async def _validate_credential(self, credential: Dict[str, Any]) -> ValidationResult:
        """Validate a single credential"""
        cred_type = credential['type'].lower()
        
        # Determine which validator to use
        validator = None
        if 'aws' in cred_type:
            validator = self.validators['aws']
        elif any(service in cred_type for service in ['sendgrid', 'mailgun', 'postmark']):
            validator = self.validators['email']
        elif 'twilio' in cred_type:
            validator = self.validators['sms']
        elif 'smtp' in cred_type:
            validator = self.validators['smtp']
        elif any(db in cred_type for db in ['mysql', 'postgres', 'mongodb']):
            validator = self.validators['database']
        
        if validator:
            try:
                result = await validator.validate(credential)
                return ValidationResult(
                    credential_type=cred_type,
                    credential_value=credential['value'],
                    status=result['status'],
                    details=result.get('details', {})
                )
            except Exception as e:
                return ValidationResult(
                    credential_type=cred_type,
                    credential_value=credential['value'],
                    status='error',
                    details={},
                    error=str(e)
                )
        else:
            return ValidationResult(
                credential_type=cred_type,
                credential_value=credential['value'],
                status='unknown',
                details={'reason': 'No validator available'}
            )