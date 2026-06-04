import logging

logger = logging.getLogger(__name__)


def process_users(data):
    if data is None:
        logger.warning("No data provided")
        return []

    results = []
    for item in data:
        validated = validate_item(item)
        if validated is not None:
            transformed = transform_item(validated)
            results.append(transformed)
            logger.info("Processed item: %s", transformed)

    return results
