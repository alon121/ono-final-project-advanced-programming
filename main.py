from webtech_inspector.models import ScanTarget, ContentEndpoint, MetaDataEndpoint


def demo_models():
    print("=== Models demo ===")
    target = ScanTarget("T001", "https://demo.example.test")

    homepage = ContentEndpoint("E001", "<script src='jquery-3.4.1.min.js'></script>", "homepage", "/", 200, "HTML")
    headers = MetaDataEndpoint("E002", "X-Powered-By: Express", "headers", "headers")
    target.add_endpoint(homepage)
    target.add_endpoint(headers)

    print(target)
    print(repr(target))
    print("Endpoints:", target.endpoints)
    print("Homepage successful?", homepage.is_successful)

    print("Find E002:", target.find_endpoint("E002"))
    print("Find E999:", target.find_endpoint("E999"))

    try:
        target.add_endpoint(ContentEndpoint("E001", "", "copy", "/", 200, "HTML"))
    except ValueError as error:
        print("Error:", error)

    try:
        ContentEndpoint("E003", "", "bad", "/", 999, "HTML")
    except ValueError as error:
        print("Error:", error)

    print("Remove E002:", target.remove_endpoint("E002"))
    print("Remove E002 again:", target.remove_endpoint("E002"))
    print("Endpoints left:", len(target))


def main():
    print("WebTech Inspector - Stage 1 (local synthetic data only)")
    demo_models()


if __name__ == "__main__":
    main()
