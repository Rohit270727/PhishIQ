from detectors.url_analyzer import analyze_url
import detectors.url_analyzer as ua

url = "https://xn--caf-dma.example.com/menu"
result = analyze_url(url)
print("score:", result["score"])
print("verdict:", result["verdict"])
for reason, pts in result["flags"]:
    print(f"  [{pts:+}] {reason}")
