"""REX Interview -- onboarding wizard and preference collection.

Public API
----------
- :class:`QuestionEngine` -- generates contextual questions from network data
- :class:`AnswerProcessor` -- validates and persists answers to the KB
- :class:`InterviewService` -- long-running service coordinating the flow
- :func:`get_basic_questions` / :func:`get_advanced_questions` -- question bank accessors
"""

from rex.interview.engine import QuestionEngine
from rex.interview.processor import AnswerProcessor
from rex.interview.question_bank import (
    ALL_QUESTIONS,
    ADVANCED_QUESTIONS,
    BASIC_QUESTIONS,
    get_advanced_questions,
    get_basic_questions,
    get_question_by_id,
    get_questions_for_mode,
)
from rex.interview.service import InterviewService

__all__ = [
    "ALL_QUESTIONS",
    "ADVANCED_QUESTIONS",
    "AnswerProcessor",
    "BASIC_QUESTIONS",
    "InterviewService",
    "QuestionEngine",
    "get_advanced_questions",
    "get_basic_questions",
    "get_question_by_id",
    "get_questions_for_mode",
]
