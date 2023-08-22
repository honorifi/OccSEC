import socket
import argparse

conn_times = 2

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("peer_rank", type=int, choices=[0,1], help="0 for master node, 1 for compute node")
    parser.add_argument("-n", "--num", type=int, default=1, help="num of msg")
    args = parser.parse_args()
    peer_rank = args.peer_rank
    if peer_rank == 0:
        sk = socket.socket()
        sk.bind(('localhost', 8898))
        print("master node listenning...")
        sk.listen()
        for _i in range(0, conn_times):
            conn, addr = sk.accept()
            print(f"connect with ip: {addr}")
            num = int.from_bytes(conn.recv(2), "big")
            print(f"msg nums: {num}")
            while num:
                num -= 1
                ret = conn.recv(1024).decode('utf-8')
                print(f"recv: \'{ret}\'")
                conn.send(bytes("recv: \'%s\'"%ret, encoding='utf-8'))
            conn.close()
        sk.close()
    else:
        for _i in range(0, conn_times):
            num = args.num
            sk = socket.socket()
            sk.connect(('localhost', 8898))
            print("connect success...")
            sk.send(num.to_bytes(2, "big"))
            while num:
                num -= 1
                info = input("")
                sk.send(bytes(info, encoding='utf-8'))
                ret = sk.recv(1024).decode('utf-8')
                print(f"master node reply: {ret}")
            sk.close()