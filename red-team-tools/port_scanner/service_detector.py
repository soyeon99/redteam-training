import requests
import json
from datetime import datetime
from pathlib import Path

class ServiceDetector:
    def __init__(self):
        self.results_dir = Path(__file__).parent / "results"
        self.timeout = 5
        # SSL 경고 무시
        requests.packages.urllib3.disable_warnings()
    
    def detect_web_services(self, scan_results):
        """
        포트 스캔 결과에서 HTTP/HTTPS 서비스 탐지
        
        Args:
            scan_results: nmap_scanner.py의 결과 딕셔너리
        """
        print("\n" + "="*60)
        print(" HTTP 서비스 탐지 시작")
        print("="*60 + "\n")
        
        target = scan_results.get('target', 'unknown')
        open_ports = scan_results.get('open_ports', [])
        
        web_services = []
        
        # HTTP/HTTPS 관련 포트 및 서비스 필터링
        http_indicators = ['http', 'https', 'ssl', 'web']
        common_web_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090]
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service'].lower()
            
            # HTTP 관련 서비스인지 확인
            is_http = any(indicator in service for indicator in http_indicators)
            
            if is_http or port in common_web_ports:
                print(f"[*] 포트 {port} 분석 중...")
                
                # HTTP와 HTTPS 둘 다 시도
                for protocol in ['http', 'https']:
                    url = f"{protocol}://{target}:{port}"
                    service_info = self._analyze_service(url)
                    
                    if service_info:
                        service_info['port'] = port
                        service_info['original_service'] = port_info['service']
                        web_services.append(service_info)
                        break
        
        # 결과 출력
        self._display_web_services(web_services)
        
        # 결과 저장
        if web_services:
            self._save_web_services(target, web_services)
        
        return web_services
    
    def _analyze_service(self, url):
        """특정 URL의 웹 서비스 분석"""
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            service_info = {
                'url': url,
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', ''),
                'framework': self._detect_framework(response),
                'technologies': self._detect_technologies(response),
                'title': self._extract_title(response.text),
                'content_type': response.headers.get('Content-Type', ''),
            }
            
            return service_info
            
        except requests.exceptions.SSLError:
            print(f"  └─ SSL 오류")
            return None
        except requests.exceptions.ConnectionError:
            print(f"  └─ 연결 실패")
            return None
        except requests.exceptions.Timeout:
            print(f"  └─ 타임아웃")
            return None
        except Exception as e:
            print(f"  └─ 오류: {str(e)[:50]}")
            return None
    
    def _detect_framework(self, response):
        """웹 프레임워크 탐지"""
        frameworks = []
        headers = response.headers
        content = response.text.lower()
        
        # 헤더 기반
        powered_by = headers.get('X-Powered-By', '')
        if 'PHP' in powered_by:
            frameworks.append('PHP')
        elif 'Express' in powered_by:
            frameworks.append('Express.js')
        elif 'ASP.NET' in powered_by:
            frameworks.append('ASP.NET')
        
        # Server 헤더
        server = headers.get('Server', '').lower()
        if 'tomcat' in server:
            frameworks.append('Apache Tomcat')
        elif 'jetty' in server:
            frameworks.append('Jetty')
        elif 'nginx' in server:
            frameworks.append('Nginx')
        elif 'apache' in server:
            frameworks.append('Apache')
        
        # 컨텐츠 기반
        if 'django' in content:
            frameworks.append('Django')
        elif 'spring' in content or 'whitelabel error page' in content:
            frameworks.append('Spring Boot')
        elif 'laravel' in content:
            frameworks.append('Laravel')
        
        # 쿠키 기반
        cookies = headers.get('Set-Cookie', '')
        if 'JSESSIONID' in cookies:
            frameworks.append('Java/Servlet')
        elif 'PHPSESSID' in cookies:
            frameworks.append('PHP')
        
        return list(set(frameworks))
    
    def _detect_technologies(self, response):
        """기술 스택 탐지"""
        technologies = []
        content = response.text.lower()
        
        # JavaScript 라이브러리
        if 'jquery' in content:
            technologies.append('jQuery')
        if 'bootstrap' in content:
            technologies.append('Bootstrap')
        if 'react' in content:
            technologies.append('React')
        if 'vue' in content:
            technologies.append('Vue.js')
        if 'angular' in content:
            technologies.append('Angular')
        
        # API 관련
        if 'swagger' in content:
            technologies.append('Swagger')
        if 'graphql' in content:
            technologies.append('GraphQL')
        if 'rest' in content or 'restful' in content:
            technologies.append('REST API')
        
        return technologies
    
    def _extract_title(self, html):
        """HTML title 추출"""
        import re
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]  # 최대 100자
        return 'No title'
    
    def _display_web_services(self, web_services):
        """결과 출력"""
        if not web_services:
            print("\n[!] 웹 서비스를 찾을 수 없습니다.\n")
            return
        
        print(f"\n 발견된 웹 서비스: {len(web_services)}개\n")
        
        for idx, service in enumerate(web_services, 1):
            print(f"{'='*60}")
            print(f"[{idx}] {service['url']}")
            print(f"{'='*60}")
            print(f"   상태: {service['status_code']}")
            print(f"    서버: {service['server']}")
            
            if service['powered_by']:
                print(f"   Powered By: {service['powered_by']}")
            
            if service['framework']:
                print(f"   프레임워크: {', '.join(service['framework'])}")
            
            if service['technologies']:
                print(f"   기술: {', '.join(service['technologies'])}")
            
            print(f"   제목: {service['title']}")
            print()
    
    def _save_web_services(self, target, web_services):
        """결과 저장"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_clean = target.replace(':', '_').replace('/', '_').replace('.', '_')
        filename = self.results_dir / f"web_services_{target_clean}_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(web_services, f, indent=2, ensure_ascii=False)
        
        print(f"[+] 결과 저장: {filename}\n")


def main():
    """스탠드얼론 실행용"""
    print("\n" + "="*60)
    print(" HTTP 서비스 탐지기")
    print("="*60 + "\n")
    
    detector = ServiceDetector()
    
    # 최신 스캔 결과 찾기
    scan_files = sorted(detector.results_dir.glob("scan_*.json"), reverse=True)
    
    if not scan_files:
        print("[!] 포트 스캔 결과가 없습니다.")
        print("[!] 먼저 port_scan.py를 실행하세요.\n")
        return
    
    print(" 최근 스캔 결과:\n")
    for idx, file in enumerate(scan_files[:5], 1):
        print(f"  {idx}. {file.name}")
    
    choice = input("\n분석할 파일 번호 (Enter = 최신): ").strip()
    
    if choice and choice.isdigit():
        selected = scan_files[int(choice) - 1]
    else:
        selected = scan_files[0]
    
    print(f"\n[*] 분석: {selected.name}\n")
    
    # 파일 로드 및 분석
    with open(selected, 'r') as f:
        scan_results = json.load(f)
    
    detector.detect_web_services(scan_results)


if __name__ == "__main__":
    main()