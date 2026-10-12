import os
from http.server import SimpleHTTPRequestHandler, HTTPServer

PORT = 8080
SAVE_DIR = "./uploaded_files"

if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR)

class CustomUploadHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        try:
            # 获取内容长度
            content_length = int(self.headers['Content-Length'])
            # 获取文件名（从自定义 Request Header 中读取，防止多部分表单解析失败）
            filename = self.headers.get('X-File-Name', 'uploaded_file.txt')
            
            # 安全过滤文件名，防止路径穿越漏洞
            filename = os.path.basename(filename)
            file_path = os.path.join(SAVE_DIR, filename)
            
            # 读取原始二进制数据并写入文件
            file_data = self.rfile.read(content_length)
            with open(file_path, 'wb') as f:
                f.write(file_data)
                
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Success: Saved to {filename}\n".encode())
            print(f"[+] 成功接收文件: {filename} ({content_length} bytes)")
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error: {str(e)}\n".encode())
            print(f"[-] 接收失败: {str(e)}")

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), CustomUploadHandler)
    print(f"[*] 正在监听端口 {PORT}，等待文件上传...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 服务器已关闭。")
