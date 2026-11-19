{ callPackage }:
callPackage ./pinned-archive.nix {
  pname = "containerd";
  version = "2.4.2";
  archives = {
    arm64 = {
      url = "https://github.com/containerd/containerd/releases/download/v2.4.2/containerd-2.4.2-linux-arm64.tar.gz";
      sha256 = "fdfab81a86192ddb8165d72f116ec985485c9e12505e323c4f4579c48020f276";
    };
    amd64 = {
      url = "https://github.com/containerd/containerd/releases/download/v2.4.2/containerd-2.4.2-linux-amd64.tar.gz";
      sha256 = "35880c1dd4627e8ce56526bfabb39c144e83458ffdb197ce6f05d17d94d7d91e";
    };
  };
  install = "install -Dm0755 -t $out/bin bin/*";
}
