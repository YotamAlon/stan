#include <filesystem>
#include "src/stan.hpp"

int main(int argc, char *argv[])
{
    std::filesystem::path file{argv[1]};
    Stan *stan;
    if (std::filesystem::exists(file)) {
        stan = new Stan(Read, std::string(argv[1]));
    } else {
        stan = new Stan(Live, std::string(argv[1]));
    }

    stan->run();
}