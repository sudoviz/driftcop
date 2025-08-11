"""
Security worker for parallel analysis in process pool
Offloads CPU-intensive security checks to separate processes
"""

import json
import multiprocessing as mp
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
import logging
import time

# Import analyzers
from ..mcp_sec.analyzers.tool_poisoning import ToolPoisoningAnalyzer
from ..mcp_sec.analyzers.cross_origin import CrossOriginAnalyzer
from ..mcp_sec.analyzers.toxic_flow import ToxicFlowAnalyzer
from ..mcp_sec.analyzers.semantic_drift import SemanticDriftAnalyzer

# Configure logging for worker processes
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global analyzers (initialized in worker process)
ANALYZERS = {}


def init_worker():
    """
    Initialize worker process with security analyzers
    Called once per worker process at startup
    """
    global ANALYZERS
    
    # Initialize analyzers
    ANALYZERS = {
        'tool_poisoning': ToolPoisoningAnalyzer(),
        'cross_origin': CrossOriginAnalyzer(),
        'toxic_flow': ToxicFlowAnalyzer(),
        'semantic_drift': SemanticDriftAnalyzer()
    }
    
    logger.info(f"Worker initialized with {len(ANALYZERS)} analyzers in PID {mp.current_process().pid}")


@dataclass
class AnalysisRequest:
    """Request for security analysis"""
    request_id: str
    message_data: Dict[str, Any]
    analyzers_to_run: list[str]
    session_context: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'request_id': self.request_id,
            'message_data': self.message_data,
            'analyzers_to_run': self.analyzers_to_run,
            'session_context': self.session_context
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisRequest':
        return cls(
            request_id=data['request_id'],
            message_data=data['message_data'],
            analyzers_to_run=data['analyzers_to_run'],
            session_context=data['session_context']
        )


@dataclass
class AnalysisResult:
    """Result of security analysis"""
    request_id: str
    findings: list[Dict[str, Any]]
    risk_scores: Dict[str, float]
    processing_time: float
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'request_id': self.request_id,
            'findings': self.findings,
            'risk_scores': self.risk_scores,
            'processing_time': self.processing_time,
            'error': self.error
        }


def analyze_message(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze message for security threats
    This runs in a worker process
    
    Args:
        request_data: Serialized AnalysisRequest
        
    Returns:
        Serialized AnalysisResult
    """
    start_time = time.time()
    
    try:
        # Parse request
        request = AnalysisRequest.from_dict(request_data)
        
        findings = []
        risk_scores = {}
        
        # Run each requested analyzer
        for analyzer_name in request.analyzers_to_run:
            if analyzer_name not in ANALYZERS:
                logger.warning(f"Unknown analyzer: {analyzer_name}")
                continue
            
            analyzer = ANALYZERS[analyzer_name]
            
            try:
                # Convert message data to MCPMessage-like object for analyzer
                from ..driftcop_proxy.message import MCPMessage, MessageDirection
                message = MCPMessage.from_dict(
                    request.message_data,
                    MessageDirection.OUTBOUND
                )
                
                # Run analysis
                analyzer_findings = analyzer.analyze(message, request.session_context)
                
                # Collect findings
                for finding in analyzer_findings:
                    finding_dict = {
                        'analyzer': analyzer_name,
                        'category': finding.category,
                        'severity': finding.severity.value,
                        'title': finding.title,
                        'description': finding.description,
                        'recommendation': finding.recommendation,
                        'metadata': finding.metadata
                    }
                    findings.append(finding_dict)
                    
                    # Track risk score
                    if finding.severity.value == 'critical':
                        risk_scores[analyzer_name] = 1.0
                    elif finding.severity.value == 'high':
                        risk_scores[analyzer_name] = max(risk_scores.get(analyzer_name, 0), 0.8)
                    elif finding.severity.value == 'medium':
                        risk_scores[analyzer_name] = max(risk_scores.get(analyzer_name, 0), 0.5)
                    elif finding.severity.value == 'low':
                        risk_scores[analyzer_name] = max(risk_scores.get(analyzer_name, 0), 0.3)
                        
            except Exception as e:
                logger.error(f"Error in analyzer {analyzer_name}: {e}")
                findings.append({
                    'analyzer': analyzer_name,
                    'category': 'error',
                    'severity': 'low',
                    'title': 'Analyzer Error',
                    'description': str(e),
                    'recommendation': 'Check analyzer configuration',
                    'metadata': {}
                })
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Create result
        result = AnalysisResult(
            request_id=request.request_id,
            findings=findings,
            risk_scores=risk_scores,
            processing_time=processing_time
        )
        
        return result.to_dict()
        
    except Exception as e:
        logger.error(f"Fatal error in analyze_message: {e}")
        return AnalysisResult(
            request_id=request_data.get('request_id', 'unknown'),
            findings=[],
            risk_scores={},
            processing_time=time.time() - start_time,
            error=str(e)
        ).to_dict()


def batch_analyze(requests: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    """
    Analyze multiple messages in batch
    More efficient for processing multiple messages
    
    Args:
        requests: List of serialized AnalysisRequests
        
    Returns:
        List of serialized AnalysisResults
    """
    results = []
    
    for request_data in requests:
        result = analyze_message(request_data)
        results.append(result)
    
    return results


class SecurityWorkerPool:
    """
    Manager for security worker pool
    Provides async interface to multiprocessing pool
    """
    
    def __init__(self, pool: mp.Pool):
        """
        Initialize worker pool manager
        
        Args:
            pool: Multiprocessing pool
        """
        self.pool = pool
        self.pending_analyses = {}
        
    async def analyze_async(
        self,
        message_data: Dict[str, Any],
        analyzers: list[str],
        session_context: Dict[str, Any]
    ) -> AnalysisResult:
        """
        Analyze message asynchronously using worker pool
        
        Args:
            message_data: Message to analyze
            analyzers: List of analyzer names to run
            session_context: Session context
            
        Returns:
            Analysis result
        """
        import uuid
        import asyncio
        
        # Create request
        request = AnalysisRequest(
            request_id=str(uuid.uuid4()),
            message_data=message_data,
            analyzers_to_run=analyzers,
            session_context=session_context
        )
        
        # Submit to pool
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(
            None,
            self.pool.apply_async,
            analyze_message,
            (request.to_dict(),)
        )
        
        # Wait for result
        result_async = await future
        result_dict = await loop.run_in_executor(None, result_async.get)
        
        # Parse result
        return AnalysisResult(
            request_id=result_dict['request_id'],
            findings=result_dict['findings'],
            risk_scores=result_dict['risk_scores'],
            processing_time=result_dict['processing_time'],
            error=result_dict.get('error')
        )
    
    async def batch_analyze_async(
        self,
        messages: list[Tuple[Dict[str, Any], list[str], Dict[str, Any]]]
    ) -> list[AnalysisResult]:
        """
        Analyze multiple messages in batch
        
        Args:
            messages: List of (message_data, analyzers, session_context) tuples
            
        Returns:
            List of analysis results
        """
        import uuid
        import asyncio
        
        # Create requests
        requests = []
        for message_data, analyzers, session_context in messages:
            request = AnalysisRequest(
                request_id=str(uuid.uuid4()),
                message_data=message_data,
                analyzers_to_run=analyzers,
                session_context=session_context
            )
            requests.append(request.to_dict())
        
        # Submit batch to pool
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(
            None,
            self.pool.apply_async,
            batch_analyze,
            (requests,)
        )
        
        # Wait for results
        results_async = await future
        results_dict = await loop.run_in_executor(None, results_async.get)
        
        # Parse results
        results = []
        for result_dict in results_dict:
            results.append(AnalysisResult(
                request_id=result_dict['request_id'],
                findings=result_dict['findings'],
                risk_scores=result_dict['risk_scores'],
                processing_time=result_dict['processing_time'],
                error=result_dict.get('error')
            ))
        
        return results
    
    def close(self):
        """Close the worker pool"""
        self.pool.close()
    
    def terminate(self):
        """Terminate the worker pool immediately"""
        self.pool.terminate()