import pytest
from scrapy.http import HtmlResponse, Request
from crawler.darknet_scraper.darknet_scraper.spiders.darknet_spider import DarknetSpider

HTML_LIST_PAGE = """
<html><body>
  <div class='threads'>
    <a class='thread-link' href='https://example.onion/thread/123'>Thread 1</a>
    <a class='thread-link' href='https://example.onion/thread/456'>Thread 2</a>
  </div>
  <a class='next' href='https://example.onion/forum?page=2'>Next</a>
</body></html>
"""

HTML_THREAD_PAGE = """
<html><body>
  <h1 class='thread-title'>Interesting Topic</h1>
  <div class='post' id='p1'>
     <span class='author'>alice</span>
     <time class='date'>2025-09-15</time>
     <div class='content'>First <b>post</b> content <a href='http://ext.site/a'>link</a></div>
  </div>
  <div class='post' id='p2'>
     <span class='author'>bob</span>
     <time class='date'>2025-09-16</time>
     <div class='content'>Second post content<img src='http://img.site/i.png'></div>
  </div>
</body></html>
"""

@pytest.fixture
def spider():
    s = DarknetSpider()
    # minimal target_sites config replicating structure loaded from settings
    s.target_sites = [{
        'name': 'ExampleForum',
        'url': 'https://example.onion/forum',
        'category': 'forum',
        'rules': {
            'follow_links': '.thread-link',
            'pagination': '.next',
            'thread_url_contains': 'thread/',
            'thread_title': '.thread-title',
            'post_container': '.post',
            'post_author': '.author',
            'post_content': '.content',
            'post_date': '.date',
            'post_id_attr': 'id'
        }
    }]
    return s


def _make_response(url: str, html: str, spider, meta=None):
    request = Request(url=url, meta=meta or {'site_config': spider.target_sites[0]})
    response = HtmlResponse(url=url, request=request, body=html, encoding='utf-8')
    response.meta['site_config'] = meta.get('site_config') if meta else spider.target_sites[0]
    return response


def test_parse_list_page_follow_and_pagination(spider):
    response = _make_response('https://example.onion/forum', HTML_LIST_PAGE, spider)
    results = list(spider.parse_list_page(response))

    # Expect 3 yielded requests: 2 thread pages + 1 pagination
    thread_requests = [r for r in results if getattr(r, 'callback', None) == spider.parse_item_page]
    pagination_requests = [r for r in results if getattr(r, 'callback', None) == spider.parse_list_page]

    assert len(thread_requests) == 2, 'Should follow two thread links'
    assert len(pagination_requests) == 1, 'Should follow one pagination link'

    followed_urls = sorted([r.url for r in thread_requests])
    assert followed_urls == [
        'https://example.onion/thread/123',
        'https://example.onion/thread/456'
    ]


def test_parse_item_page_extracts_posts(spider):
    response = _make_response('https://example.onion/thread/123', HTML_THREAD_PAGE, spider)
    items = list(spider.parse_item_page(response))

    assert len(items) == 2, 'Should yield two posts'

    first = items[0]
    second = items[1]

    # Basic field presence
    for itm in items:
        for field in ['url', 'title', 'content', 'raw_html', 'crawled_at', 'content_hash', 'site_category', 'author', 'post_id', 'thread_id']:
            assert field in itm, f'Missing field {field}'
        assert itm['url'] == 'https://example.onion/thread/123'
        assert itm['site_category'] == 'forum'
        assert itm['content']
        assert len(itm['content_hash']) == 64

    assert first['author'] == 'alice'
    assert second['author'] == 'bob'
    assert 'First post content' in first['content']
    assert 'Second post content' in second['content']

    # Links and images extraction
    assert first['links'] == ['http://ext.site/a']
    assert second['images'] == ['http://img.site/i.png']

    # Distinct post ids
    assert first['post_id'] != second['post_id']
