import ipaddress
import json

BLACKLIST = {"185.220.101.1", "45.33.32.156", "192.168.1.10"}
HIGH_RISK_COUNTRIES = {"RU", "KP", "IR"}

def classify_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "status": "Invalid IP", "risk": "Unknown"}

    if ip in BLACKLIST:
        return {"ip": ip, "status": "Blacklisted", "risk": "High"}

    # Simulated country check (placeholder logic)
    if ip.startswith("185.") or ip.startswith("45."):
        return {"ip": ip, "status": "Suspicious Region", "risk": "Medium"}

    return {"ip": ip, "status": "Clean", "risk": "Low"}


def save_result(result):
    with open("results.json", "a") as file:
        json.dump(result, file)
        file.write("\n")


def main():
    ip = input("Enter IP address to analyze: ")
    result = classify_ip(ip)
    print(f"\nAnalysis Result:")
    print(f"IP: {result['ip']}")
    print(f"Status: {result['status']}")
    print(f"Risk Level: {result['risk']}")

    save_result(result)


if __name__ == "__main__":
    main()
