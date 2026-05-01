#include <apt-pkg/hashes.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

int main() {
    const std::string path = "/tmp/apt-hashes-input.txt";
    std::ofstream(path) << "apt libgcrypt hash path\n";

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return 1;
    }

    Hashes hashes(Hashes::SHA256SUM | Hashes::SHA1SUM);
    if (!hashes.AddFD(fd, Hashes::UntilEOF)) {
        close(fd);
        return 2;
    }
    close(fd);

    std::cout << hashes.GetHashString(Hashes::SHA256SUM).HashValue() << "\n";
    std::cout << hashes.GetHashString(Hashes::SHA1SUM).HashValue() << "\n";
    return 0;
}
