"""
Base class for all modular security checks.
"""

from abc import ABC, abstractmethod
from typing import List, Dict
from scanner.client import AsyncScannerClient
from scanner.models import HTTPResponse, VulnerabilityFinding


class BaseCheck(ABC):
    """
    Abstract base class for security scanner vulnerability checks.
    """

    check_id: str = "BASE_CHECK"
    name: str = "Base Security Check"
    description: str = "Base class for scanner vulnerability checks."

    def __init__(self, client: AsyncScannerClient):
        self.client = client

    @abstractmethod
    async def run(
        self, target_url: str, responses: Dict[str, HTTPResponse]
    ) -> List[VulnerabilityFinding]:
        """
        Executes check logic across target endpoints and returns identified findings.
        """
        pass
