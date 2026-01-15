import subprocess
import sys

def main():
    print()
    print("Starting installation of extra dependencies...")
    print()

    failed = []

    # Your exact PyTorch versions
    TORCH_VERSION = "2.5.1+cu121"
    TORCHVISION_VERSION = "0.20.1+cu121"
    TORCHAUDIO_VERSION = "2.5.1+cu121"
    CUDA_URL = "https://download.pytorch.org/whl/cu121"

    # read requirements.txt
    with open("requirements.txt", "r") as f:
        packages = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    for pkg in packages:
        print("installing", pkg)
        try:
            print(f"Installing {pkg} ...")
            if "torchvision" in pkg.lower():
                subprocess.run(
                    ["python3.10", "-m", "pip", "install",
                    f"torchvision=={TORCHVISION_VERSION}",
                    "--index-url", CUDA_URL,
                    "--no-deps", "--ignore-installed"],
                    check=True
                )
            elif "torchaudio" in pkg.lower():
                subprocess.run(
                    ["python3.10", "-m", "pip", "install",
                    f"torchaudio=={TORCHAUDIO_VERSION}",
                    "--index-url", CUDA_URL,
                    "--no-deps", "--ignore-installed"],
                    check=True
                )
            elif "torch" in pkg.lower():
                subprocess.run(
                    ["python3.10", "-m", "pip", "install",
                    f"torch=={TORCH_VERSION}",
                    "--index-url", CUDA_URL,
                    "--no-deps", "--ignore-installed"],
                    check=True
                )
            else:
                subprocess.run(
                    ["python3.10", "-m", "pip", "install",
                    "--no-deps", "--ignore-installed", pkg],
                    check=True
                )
        except subprocess.CalledProcessError:
            print(f"Failed to install {pkg}")
            failed.append(pkg)

    if failed:
        print("\nThese packages failed to install:")
        for f in failed:
            print(f"- {f}")
        with open("failed_installs.txt", "w") as f:
            f.write("\n".join(failed))

    print("Installation complete")

if __name__ == "__main__":
    main()



