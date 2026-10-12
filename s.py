import socket

HOST = "0.0.0.0"
PORT = 9001

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    print(f"[*] Listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    with conn:
        print(f"[+] Client connected: {addr}")

        while True:
            command = input("server> ").strip()

            if command == "exit":
                conn.sendall(b"exit\n")
                break

            conn.sendall((command + "\n").encode())

            data = conn.recv(4096)
            if not data:
                break

            print(data.decode(errors="replace"), end="")