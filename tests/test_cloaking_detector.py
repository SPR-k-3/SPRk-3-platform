#!/usr/bin/env python3
"""Test suite for SPR{K}3 Cloaking Detector"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from detectors.cloaking_detector import (
    CloakingDetector,
    ThreatLevel,
    AnomalyType,
    FetchResult
)


class TestCloakingDetector(unittest.TestCase):
    """Test cloaking detection functionality"""
    
    def setUp(self):
        self.detector = CloakingDetector(timeout=5, verbose=False)
    
    def test_detector_initialization(self):
        """Test detector initializes correctly"""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.timeout, 5)
    
    def test_content_similarity_identical(self):
        """Test similarity calculation for identical content"""
        text = "Hello World"
        similarity = self.detector._content_similarity_ratio(text, text)
        self.assertEqual(similarity, 1.0)
    
    def test_content_similarity_different(self):
        """Test similarity calculation for different content"""
        text1 = "Hello World"
        text2 = "Goodbye Universe"
        similarity = self.detector._content_similarity_ratio(text1, text2)
        self.assertLess(similarity, 1.0)
    
    def test_threat_classification_clean(self):
        """Test threat classification for clean content"""
        threat = self.detector._classify_threat(0.01, [])
        self.assertEqual(threat, ThreatLevel.CLEAN)
    
    def test_threat_classification_critical(self):
        """Test threat classification for critical divergence"""
        threat = self.detector._classify_threat(0.35, [])
        self.assertEqual(threat, ThreatLevel.CRITICAL)


class TestCloakingDetectorIntegration(unittest.TestCase):
    """Integration tests with real URLs"""
    
    def setUp(self):
        self.detector = CloakingDetector(timeout=10, verbose=False)
    
    def test_detect_anthropic_clean(self):
        """Test that Anthropic homepage is clean"""
        result = self.detector.detect(
            'https://www.anthropic.com',
            agents=['browser_chrome', 'crawler_google']
        )
        
        self.assertEqual(len(result.fetches), 2)
        self.assertFalse(result.suspect)
        self.assertLess(result.divergence_score, 0.15)


if __name__ == '__main__':
    unittest.main()
