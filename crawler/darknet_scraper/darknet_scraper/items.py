# Define here the models for your scraped items

import scrapy


class CtiItem(scrapy.Item):
    """Item for storing CTI data."""
    
    # Basic fields
    url = scrapy.Field()
    title = scrapy.Field()
    content = scrapy.Field()
    raw_html = scrapy.Field()
    
    # Metadata
    crawled_at = scrapy.Field()
    content_hash = scrapy.Field()
    site_category = scrapy.Field()
    
    # Extracted data
    author = scrapy.Field()
    post_date = scrapy.Field()
    thread_id = scrapy.Field()
    post_id = scrapy.Field()
    
    # Additional metadata
    response_time = scrapy.Field()
    content_length = scrapy.Field()
    links = scrapy.Field()
    images = scrapy.Field()

