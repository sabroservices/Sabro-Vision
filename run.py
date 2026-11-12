import os
import sys
import argparse
import webbrowser
from waitress import serve
from app import app
import seeds

def main():
    parser = argparse.ArgumentParser(description="Sabro Vision 24/7 Production Server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8080)), help="Port to listen on (default: 8080)")
    parser.add_argument("--host", type=str, default=os.environ.get("HOST", "0.0.0.0"), help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--open", action="store_true", help="Automatically launch web browser")
    args, _ = parser.parse_known_args()

    # Initialize and seed if needed
    seeds.seed_database(force_reset=False)

    host = args.host
    port = args.port
    local_url = f"http://127.0.0.1:{port}"

    print("==================================================")
    print("               SABRO VISION SERVER                ")
    print("    Powered by Sabro Networks Fiber Internet      ")
    print("==================================================")
    print(f"\n[+] Sabro Vision is online 24/7!")
    print(f"    Web Player:  {local_url}")
    print(f"    Admin Panel: {local_url}/admin (User: ahmedbaloch)")
    print(f"\n[+] Running on http://{host}:{port} (Multi-threaded Waitress WSGI)...")

    # Automatically launch default browser if requested
    if args.open:
        try:
            webbrowser.open(local_url)
        except Exception:
            pass

    # Run multi-threaded production WSGI server
    serve(app, host=host, port=port, threads=16, connection_limit=500, channel_timeout=60)

if __name__ == "__main__":
    main()
