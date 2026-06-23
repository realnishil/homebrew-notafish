class Notafish < Formula
  desc "Heuristic phishing URL checker"
  homepage "https://github.com/realnishil/NotAFish"
  url "https://github.com/realnishil/NotAFish/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "04746e07f1561f85256e96e6d55095bdb11719d7ca0608e506ae0ebac7c7de71"
  license "MIT"

  depends_on "python@3.12"

  def install
    bin.install "notafish.py" => "notafish"
  end

  test do
    system "#{bin}/notafish", "--help"
  end
end
