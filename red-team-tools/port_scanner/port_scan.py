import nmap
import json
from datetime import datetime
from pathlib import Path

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results_dir = Path(__file__).parent / "results"
        self.results_dir.mkdir(exist_ok=True)
    
    def quick_scan(self, target):
        """빠른 스캔 (주요 1000개 포트)"""
        print(f"\n[*] 타겟: {target}")
        print(f"[*] 스캔 시작...\n")
        
        try:
            # -Pn 옵션 추가 (Ping 건너뛰기)
            self.nm.scan(target, arguments="-Pn -sV -T4")
            
            # 디버깅 출력
            print(f"[DEBUG] 스캔된 호스트: {self.nm.all_hosts()}")
            
            results = {
                "target": target,
                "scan_time": datetime.now().isoformat(),
                "open_ports": []
            }
            
            # 호스트 확인
            all_hosts = self.nm.all_hosts()
            
            if not all_hosts:
                print("[!] 호스트를 찾을 수 없습니다.")
                return results
            
            # 첫 번째 호스트 사용 (도메인이 IP로 변환된 경우 대비)
            scanned_host = all_hosts[0]
            print(f"[DEBUG] 분석 중인 호스트: {scanned_host}")
            
            if 'tcp' in self.nm[scanned_host]:
                tcp_ports = self.nm[scanned_host]['tcp']
                print(f"[DEBUG] 발견된 TCP 포트: {list(tcp_ports.keys())}")
                
                for port in tcp_ports:
                    port_data = tcp_ports[port]
                    print(f"[DEBUG] 포트 {port}: {port_data['state']}")
                    
                    if port_data['state'] == 'open':
                        results['open_ports'].append({
                            "port": port,
                            "service": port_data.get('name', 'unknown'),
                            "product": port_data.get('product', ''),
                            "version": port_data.get('version', '')
                        })
            else:
                print("[DEBUG] TCP 프로토콜 정보 없음")
            
            self._display_results(results)
            self._save_results(results)
            
            return results
            
        except Exception as e:
            print(f"[!] 오류 발생: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def full_scan(self, target):
        """전체 포트 스캔 (1-65535)"""
        print(f"\n[*] 타겟: {target}")
        print(f"[*] 전체 포트 스캔 시작...\n")
        
        try:
            # -Pn 옵션 추가
            self.nm.scan(target, "1-65535", arguments="-Pn -sV -T4")
            
            results = {
                "target": target,
                "scan_time": datetime.now().isoformat(),
                "scan_type": "full",
                "open_ports": []
            }
            
            all_hosts = self.nm.all_hosts()
            
            if not all_hosts:
                print("[!] 호스트를 찾을 수 없습니다.")
                return results
            
            scanned_host = all_hosts[0]
            
            if 'tcp' in self.nm[scanned_host]:
                for port in self.nm[scanned_host]['tcp']:
                    port_data = self.nm[scanned_host]['tcp'][port]
                    
                    if port_data['state'] == 'open':
                        results['open_ports'].append({
                            "port": port,
                            "service": port_data.get('name', 'unknown'),
                            "product": port_data.get('product', ''),
                            "version": port_data.get('version', '')
                        })
            
            self._display_results(results)
            self._save_results(results)
            
            return results
            
        except Exception as e:
            print(f"[!] 오류 발생: {e}")
            return None
    
    def _display_results(self, results):
        """콘솔에 결과 출력"""
        print("\n" + "="*60)
        print(f" 스캔 결과: {results['target']}")
        print("="*60)
        
        if not results['open_ports']:
            print("\n[!] 열린 포트가 없습니다.\n")
            return
        
        print(f"\n 열린 포트: {len(results['open_ports'])}개\n")
        print(f"{'포트':<8} {'서비스':<15} {'제품/버전'}")
        print("-"*60)
        
        for p in results['open_ports']:
            service_info = f"{p['product']} {p['version']}".strip()
            if not service_info:
                service_info = "-"
            print(f"{p['port']:<8} {p['service']:<15} {service_info}")
        
        print()
    
    def _save_results(self, results):
        """JSON 파일로 저장"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_clean = results['target'].replace(':', '_').replace('/', '_')
        filename = self.results_dir / f"scan_{target_clean}_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"[+] 결과 저장됨: {filename}\n")


def main():
    print("\n" + "="*60)
    print(" RED TEAM - 포트 스캐너")
    print("="*60 + "\n")
    
    scanner = PortScanner()
    
    target = input("타겟 IP 또는 도메인 입력: ").strip()
    
    if not target:
        print("[!] 타겟을 입력해주세요.")
        return
    
    print("\n스캔 모드 선택:")
    print("1. 빠른 스캔 (Top 1000 포트)")
    print("2. 전체 스캔 (1-65535 포트)")
    
    choice = input("\n선택 (1 또는 2): ").strip()
    
    if choice == "2":
        scanner.full_scan(target)
    else:
        scanner.quick_scan(target)


if __name__ == "__main__":
    main()