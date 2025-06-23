Proje Hakkında

Bu Python script'i, Sunucu Tarafı İstek Sahteciliği (Server-Side Request Forgery - SSRF) zafiyetlerini tespit etmek amacıyla geliştirilmiştir. Belirtilen bir URL şablonuna çeşitli SSRF payload'larını enjekte ederek, hedef sistemin dahili ağ kaynaklarına veya hassas meta verilerine erişim sağlayıp sağlamadığını kontrol eder. Script, web uygulamalarındaki yanlış yapılandırmalar veya güvenli olmayan kodlama pratikleri nedeniyle ortaya çıkabilecek SSRF zafiyetlerini proaktif olarak bulmayı hedefler.
✨ Özellikler

    Kapsamlı Payload Listesi: Yerel ağ adresleri (localhost, 127.0.0.1, 0.0.0.0), AWS ve Google Cloud meta veri servisleri, dosya sistemi erişimi (file:///etc/passwd), farklı IP adresi formatları (onluk, onaltılık, sekizlik), port taramaları ve URL kodlamaları gibi geniş bir yelpazede SSRF payload'ları içerir.
    Çoklu HTTP Metod Desteği: GET, POST ve PUT HTTP metodları ile istek göndererek farklı uygulama davranışlarını tetikleme potansiyeli sunar.
    Akıllı Hassas İçerik Tespiti: Sunucu yanıtlarında "root:", "meta-data", "admin", "private", "internal", "AWS", "credentials" gibi hassas anahtar kelimeleri arayarak potansiyel zafiyetleri belirler.
    Detaylı Raporlama: Tespit edilen her potansiyel zafiyet için kullanılan metod, URL, payload, HTTP durum kodu, yanıt içeriğinin bir kısmı ve zafiyetin neden olası olduğu ile çözüm önerilerini konsola yazdırır.
    Hata Yönetimi: Ağ bağlantı sorunları veya geçersiz URL'ler gibi durumlarda oluşan hataları yakalar ve loglar.

🚀 Hızlı Başlangıç

Bu aracı kullanmak için ihtiyacınız olanlar:

    Python 3: Script Python 3 ile yazılmıştır.
    requests kütüphanesi: HTTP istekleri yapmak için kullanılır.

1. Gerekli Kütüphaneyi Kurun

Script'i çalıştırmadan önce, Python ortamınızda requests kütüphanesinin kurulu olduğundan emin olun:
Bash

pip install requests

2. Script'i İndirin

Bu projenin GitHub deposundan idsresponsescan.py dosyasını indirin veya kopyalayın.
3. Script'i Çalıştırın

Terminalinizde script'in bulunduğu dizine gidin ve aşağıdaki komutu çalıştırın. Script sizden taramak istediğiniz hedef domain'i isteyecektir.
Bash

python idsresponsescan.py

İstendiğinde hedef domain'i girin:

Enter the domain to scan for SSRF vulnerabilities (e.g., example.com): example.com

Script, belirlediğiniz domain'e http://<domain>?url={payload} formatında istekler gönderecektir. Eğer uygulamanızın SSRF zafiyetinin bulunduğu parametre adı farklıysa, script'in target_url_template değişkenini kendinize göre düzenlemeniz gerekebilir. Örneğin: f"http://{target_domain}/api/fetch?image_url={{}}"
📈 Bulguları Değerlendirme

Tarama tamamlandığında, terminalde tespit edilen tüm potansiyel SSRF zafiyetlerini göreceksiniz. Her bulgu için aşağıdaki bilgiler listelenir:

    Method: Kullanılan HTTP metodu (GET, POST, PUT).
    URL: İsteğin gönderildiği tam URL.
    Payload: Kullanılan SSRF payload'ı.
    Status: Sunucudan dönen HTTP durum kodu.
    Content: Sunucu yanıtının ilk 200 karakteri. Bu kısım, potansiyel hassas bilgileri (örneğin, dosya içeriği, meta veri çıktısı) içerebilir.
    Why Vulnerable: Neden zafiyet olarak kabul edildiğine dair kısa bir açıklama.
    Mitigation: Zafiyeti düzeltmek için önerilen genel yöntemler.

Önemli Not: Bu tarayıcı bir otomatik araç olup, sonuçlar hatalı pozitifler (false positives) içerebilir. Yanıtta bulunan anahtar kelimeler her zaman gerçek bir SSRF zafiyetini işaret etmeyebilir. Tespit edilen her bulguyu manuel olarak doğrulamanız ve potansiyel etkisini teyit etmeniz kritik öneme sahiptir. Örneğin, file:///etc/passwd payload'ı ile 200 durum kodu dönse bile, yanıtın gerçekten /etc/passwd dosyasının içeriğini içerdiğini doğrulamalısınız.
💡 Geliştirme Önerileri

Bu script'i daha da güçlü hale getirmek için aklında bulunması gereken bazı fikirler:

    Daha Akıllı Yanıt Analizi: Sadece anahtar kelime tabanlı kontrol yerine, yanıt başlıklarını, içerik türünü ve yanıtın uzunluğunu daha detaylı analiz etmek, hatalı pozitifleri azaltabilir. Örneğin, file okumalarında dosya büyüklüğünün veya özel karakterlerin kontrolü.
    Out-of-Band (OOB) Etkileşimler: http://burpcollaborator.net veya kendi barındırdığınız bir sunucuya (örneğin ngrok ile) istek göndererek sunucunun dışarıya doğru bağlantı kurup kurmadığını kontrol edebilirsiniz. Bu, yanıt içeriği dönmeyen "blind SSRF" durumlarında çok etkilidir.
    Daha Fazla Payload Çeşitliliği: URL encode seviyelerini artırmak, farklı protokolleri denemek (gopher, dict, ftp, sftp), port atlama (port-bouncing) tekniklerini dahil etmek.
    Proxy Desteği: İsteğe bağlı olarak bir proxy (örneğin Burp Suite) üzerinden istekleri geçirme yeteneği, debug ve manuel analiz için faydalı olabilir.
    Çoklu Hedef Desteği: Bir .txt dosyasından URL listesi okuyarak birden fazla hedefi aynı anda tarama özelliği eklemek.
    Raporlama Çıktısı: Bulguları bir JSON, CSV veya HTML dosyasına kaydetme seçeneği eklemek.

🤝 Katkıda Bulunma

Proje daha fazla geliştirmeye açık! Yeni payload'lar eklemek, yanıt analizini iyileştirmek, hata yönetimi geliştirmeleri yapmak veya yeni özellikler önermek isterseniz, geri bildirimleriniz, hata raporlarınız ve katkılarınız her zaman açığız. Bir çekme isteği (pull request) göndermeden önce lütfen mevcut sorunları kontrol edin veya yeni bir sorun açın.
📄 Lisans

Bu proje MIT Lisansı altında yayınlanmıştır. Daha fazla bilgi için LICENSE dosyasına bakın.
📧 İletişim

Sorularınız, önerileriniz veya işbirliği talepleriniz için bana github.com/0batexe1 üzerinden ulaşabilirsiniz.
English Version
SSRF Scanner
🔍 About The Project

This Python script is designed to detect Server-Side Request Forgery (SSRF) vulnerabilities. It injects various SSRF payloads into a specified URL template to check whether the target system can be made to access internal network resources or sensitive metadata. The script aims to proactively find SSRF vulnerabilities that may arise due to misconfigurations or insecure coding practices in web applications.
✨ Features

    Comprehensive Payload List: Includes a wide range of SSRF payloads such as local network addresses (localhost, 127.0.0.1, 0.0.0.0), AWS and Google Cloud metadata services, file system access (file:///etc/passwd), different IP address formats (decimal, hexadecimal, octal), port scans, and URL encodings.
    Multiple HTTP Method Support: Sends requests using GET, POST, and PUT HTTP methods to potentially trigger different application behaviors.
    Intelligent Sensitive Content Detection: Identifies potential vulnerabilities by searching for sensitive keywords like "root:", "meta-data", "admin", "private", "internal", "AWS", "credentials" in server responses.
    Detailed Reporting: Prints detected potential vulnerabilities to the console, including the method used, URL, payload, HTTP status code, a portion of the response content, an explanation of why it might be vulnerable, and mitigation suggestions.
    Error Handling: Catches and logs errors such as network connection issues or invalid URLs.

🚀 Quick Start

To use this tool, you'll need:

    Python 3: The script is written in Python 3.
    requests library: Used for making HTTP requests.

1. Install Required Libraries

Before running the script, ensure that the requests library is installed in your Python environment:
Bash

pip install requests

2. Download the Script

Download or copy the idsresponsescan.py file from this project's GitHub repository.
3. Run the Script

Navigate to the directory where you saved the script in your terminal and run the following command. The script will prompt you for the target domain you wish to scan.
Bash

python idsresponsescan.py

Enter the target domain when prompted:

Enter the domain to scan for SSRF vulnerabilities (e.g., example.com): example.com

The script will send requests to your specified domain using the format http://<domain>?url={payload}. If the vulnerable parameter in your application has a different name, you might need to adjust the target_url_template variable in the script. For example: f"http://{target_domain}/api/fetch?image_url={{}}"
📈 Evaluating Findings

Once the scan is complete, you will see all detected potential SSRF vulnerabilities in your terminal. Each finding lists the following information:

    Method: The HTTP method used (GET, POST, PUT).
    URL: The full URL to which the request was sent.
    Payload: The SSRF payload used.
    Status: The HTTP status code returned by the server.
    Content: The first 200 characters of the server response. This section may contain potentially sensitive information (e.g., file contents, metadata output).
    Why Vulnerable: A brief explanation of why it is considered a potential vulnerability.
    Mitigation: General suggestions for fixing the vulnerability.

Important Note: This scanner is an automated tool, and the results may contain false positives. Keywords found in the response do not always indicate a true SSRF vulnerability. It is crucial to manually verify each detected finding and confirm its potential impact. For instance, even if a file:///etc/passwd payload returns a 200 status code, you must confirm that the response actually contains the content of the /etc/passwd file.
💡 Improvement Suggestions

Here are some ideas to make this script even more powerful:

    Smarter Response Analysis: Beyond simple keyword checks, a more detailed analysis of response headers, content type, and response length could reduce false positives. For example, checking for specific file sizes or unique characters in file read operations.
    Out-of-Band (OOB) Interactions: Send requests to http://burpcollaborator.net or your own hosted server (e.g., via ngrok) to check if the server makes outbound connections. This is highly effective for "blind SSRF" scenarios where the response content is not returned.
    More Payload Diversity: Increase URL encoding levels, try different protocols (gopher, dict, ftp, sftp), and include port-bouncing techniques.
    Proxy Support: Add the ability to optionally route requests through a proxy (e.g., Burp Suite) for easier debugging and manual analysis.
    Multiple Target Support: Implement functionality to read a list of URLs from a .txt file to scan multiple targets concurrently.
    Reporting Output: Add an option to save findings to a JSON, CSV, or HTML file.

🤝 Contributing

The project is open for further development! If you'd like to add new payloads, improve response analysis, enhance error handling, or suggest new features, your feedback, bug reports, and contributions are always welcome. Please check for existing issues or open a new one before submitting a pull request.
📄 License

This project is licensed under the MIT License. See the LICENSE file for more details.
📧 Contact

For any questions, suggestions, or collaboration inquiries, feel free to reach out to me via github.com/0batexe1.
