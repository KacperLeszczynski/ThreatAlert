class FeedSourceError(RuntimeError):
    """Base error for one configured feed source."""


class PermanentFeedError(FeedSourceError):
    """Failure that must not be retried."""


class TransientFeedError(FeedSourceError):
    """Failure that exhausted the bounded retry policy."""
