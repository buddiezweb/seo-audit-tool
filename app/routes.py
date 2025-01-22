from flask import Blueprint, render_template, request, jsonify, current_app
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import time
from bs4 import BeautifulSoup as BSHTML
import urllib
import base64
import io
from PIL import Image
import re

main = Blueprint('main', __name__)

@main.route('/')
@main.route('/index')
def index():
    return render_template('index.html')

class TechnicalSEOAudit:
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.results = {
            'basic_info': {},
            'security': {},
            'performance': {},
            'meta_tags': {},
            'headers': {},
            'links': {},
            'images': {}
        }

    def run_full_audit(self):
        try:
            response = requests.get(self.url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            self.check_basic_info(response)
            self.check_security(response)
            self.check_performance(response)
            self.analyze_meta_tags(soup)
            self.analyze_headers(soup)
            self.analyze_links(soup)
            self.analyze_images(soup)
            
            return self.results
            
        except Exception as e:
            return {'error': str(e)}

    def check_basic_info(self, response):
        self.results['basic_info'] = {
            'status_code': response.status_code,
            'response_time': f"{response.elapsed.total_seconds():.2f}s",
            'content_type': response.headers.get('content-type', 'Not specified'),
            'url': self.url,
            'domain': self.parsed_url.netloc
        }

    def check_security(self, response):
        self.results['security'] = {
            'https_enabled': self.url.startswith('https'),
            'security_headers': {
                'strict_transport_security': response.headers.get('Strict-Transport-Security', 'Not set'),
                'x_content_type_options': response.headers.get('X-Content-Type-Options', 'Not set'),
                'x_frame_options': response.headers.get('X-Frame-Options', 'Not set'),
                'content_security_policy': response.headers.get('Content-Security-Policy', 'Not set')
            }
        }

    def check_performance(self, response):
        self.results['performance'] = {
            'page_size': f"{len(response.content) / 1024:.2f} KB",
            'load_time': f"{response.elapsed.total_seconds():.2f}s"
        }

    def analyze_meta_tags(self, soup):
        meta_tags = soup.find_all('meta')
        self.results['meta_tags'] = {
            'title': soup.title.string if soup.title else 'No title found',
            'meta_description': next((meta.get('content') for meta in meta_tags if meta.get('name') == 'description'), 'No meta description found'),
            'viewport': next((meta.get('content') for meta in meta_tags if meta.get('name') == 'viewport'), 'No viewport meta tag found'),
            'robots': next((meta.get('content') for meta in meta_tags if meta.get('name') == 'robots'), 'No robots meta tag found'),
            'charset': soup.meta.get('charset') if soup.meta else 'Not specified'
        }

    def analyze_headers(self, soup):
        headers = {}
        for i in range(1, 7):
            h_tags = soup.find_all(f'h{i}')
            headers[f'h{i}'] = {
                'count': len(h_tags),
                'content': [tag.get_text(strip=True) for tag in h_tags]
            }
        self.results['headers'] = headers

    # Update the analyze_links method in TechnicalSEOAudit class
    def analyze_links(self, soup):
        links = soup.find_all('a')
        internal_links = []
        external_links = []
        
        for link in links:
            href = link.get('href')
            text = link.get_text(strip=True)
            if href:
                link_data = {
                    'url': href,
                    'text': text or '[No Text]',
                    'title': link.get('title', ''),
                    'rel': link.get('rel', [])
                }
                
                if href.startswith(('http', 'https')):
                    if self.parsed_url.netloc in href:
                        internal_links.append(link_data)
                    else:
                        external_links.append(link_data)
                elif href.startswith('/'):
                    link_data['url'] = f"https://{self.parsed_url.netloc}{href}"
                    internal_links.append(link_data)
                    
        self.results['links'] = {
            'summary': {
                'total_links': len(links),
                'internal_links': len(internal_links),
                'external_links': len(external_links)
            },
            'internal_links': internal_links,
            'external_links': external_links
        }


    def decode_base64_image(self, base64_string):
        try:
            # Handle direct URLs
            if isinstance(base64_string, str) and (base64_string.startswith('http') or base64_string.startswith('//')):
                return {
                    'type': 'url',
                    'src': base64_string,
                    'format': base64_string.split('.')[-1].lower(),  # Get format from URL extension
                    'size': None,
                    'mode': None
                }

            # Convert bytes to string if needed
            if isinstance(base64_string, bytes):
                svg_string = base64_string.decode('utf-8')
            else:
                svg_string = base64_string

            # Check if it's an SVG with data-u attribute
            if '<svg' in svg_string:
                data_u_match = re.search(r'data-u="([^"]+)"', svg_string)
                if data_u_match:
                    actual_url = urllib.parse.unquote(data_u_match.group(1))
                    return {
                        'type': 'url',
                        'src': actual_url,
                        'format': actual_url.split('.')[-1].lower(),
                        'size': None,
                        'mode': None
                    }
            
            # Handle base64 images
            elif 'data:image' in svg_string:
                pattern = r'data:image/(?P<format>.*?);base64,(?P<data>.*)'
                match = re.match(pattern, svg_string)
                if match:
                    image_format = match.group('format')
                    base64_data = match.group('data')
                    
                    image_data = base64.b64decode(base64_data)
                    try:
                        svg_string = image_data.decode('utf-8')
                        data_u_match = re.search(r'data-u="([^"]+)"', svg_string)
                        if data_u_match:
                            actual_url = urllib.parse.unquote(data_u_match.group(1))
                            return {
                                'type': 'url',
                                'src': actual_url,
                                'format': actual_url.split('.')[-1].lower(),
                                'size': None,
                                'mode': None
                            }
                    except UnicodeDecodeError:
                        # If it's not decodable as UTF-8, it's probably a real image
                        image = Image.open(io.BytesIO(image_data))
                        return {
                            'type': 'base64',
                            'format': image_format,
                            'size': image.size,
                            'mode': image.mode,
                            'src': None
                        }
            
            return None
        
        except Exception as e:
            print(f"Error decoding image: {str(e)}")
            return None       

    # Update the TechnicalSEOAudit class with enhanced image analysis
    def analyze_images(self, soup):
        images = soup.find_all('img')
        image_data = []
        
        for img in images:
            src = (img.get('data-original-src') or 
                img.get('data-lazy-src') or 
                img.get('data-src') or 
                img.get('src'))
            
            if not src:
                continue
            
            # Decode any type of image source
            decoded = self.decode_base64_image(src)
            if decoded:
                image_info = {
                    'type': decoded['type'],
                    'format': decoded['format'],
                    'size': decoded['size'],
                    'mode': decoded['mode']
                }
                
                # Add source URL if available
                if decoded['src']:
                    image_info['src'] = decoded['src']
                elif src.startswith(('http', '//')):
                    image_info['src'] = src
                
                image_data.append(image_info)
            else:
                # Fallback for unhandled cases
                image_data.append({
                    'type': 'url',
                    'src': src,
                    'format': src.split('.')[-1].lower() if '.' in src else None,
                    'size': None,
                    'mode': None
                })

        self.results['images'] = image_data

@main.route('/audit', methods=['POST'])
def audit():
    url = request.form.get('url')
    try:
        auditor = TechnicalSEOAudit(url)
        results = auditor.run_full_audit()
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500