#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include "auth.hpp"
#include "utils.hpp"
#include "skStr.h"

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
void sessionStatus();
bool patchFile(const std::string& filePath);

using namespace KeyAuth;

std::string name = skCrypt("Redshift_CPU").decrypt();
std::string ownerid = skCrypt("kaSzteLJcT").decrypt();
std::string version = skCrypt("1.4").decrypt();
std::string url = skCrypt("https://keyauth.win/api/1.3/").decrypt();
std::string path = skCrypt("Redshift_License_Utility.exe").decrypt();

const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);
const std::string autoLoginFile = "C:\\ProgramData\\Redshift_CPU_Login.json";

api KeyAuthApp(name, ownerid, version, url, path);

int main()
{
    std::string consoleTitle = skCrypt("Epic Motion - Built at: ").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Checking For Update...");

    KeyAuthApp.init();
    

    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }

    if (std::filesystem::exists(autoLoginFile))
    {
        if (!CheckIfJsonKeyExists(autoLoginFile, "username"))
        {
            std::string key = ReadFromJson(autoLoginFile, "license");
            KeyAuthApp.license(key);
            if (!KeyAuthApp.response.success)
            {
                std::remove(autoLoginFile.c_str());
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
                Sleep(1500);
                exit(1);
            }
            std::cout << skCrypt("\n\n Successfully Detected Device Locked License\n");
        }
        else
        {
            std::string username = ReadFromJson(autoLoginFile, "username");
            std::string password = ReadFromJson(autoLoginFile, "password");
            KeyAuthApp.login(username, password);
            if (!KeyAuthApp.response.success)
            {
                std::remove(autoLoginFile.c_str());
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
                Sleep(1500);
                exit(1);
            }
            std::cout << skCrypt("\n\n Successfully Automatically Logged In\n");
        }
    }
    else
    {
        std::cout << skCrypt("\n\n [1] Enter License Key \n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");
        int option;
        std::string username, password, key;
        std::cin >> option;

        switch (option)
        {
        case 1:
            std::cout << skCrypt("\n\n Enter Key: ");
            std::cin >> username;
            std::cout << skCrypt("\n Re-Enter Key: ");
            std::cin >> password;
            KeyAuthApp.login(username, password);
            break;
        case 2:
            std::cout << skCrypt("\n\n Enter Key: ");
            std::cin >> username;
            std::cout << skCrypt("\n Re-Enter Key: ");
            std::cin >> password;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.regstr(username, password, key);
            break;
        case 3:
            std::cout << skCrypt("\n\n Enter Key: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.upgrade(username, key);
            break;
        case 4:
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.license(key);
            break;
        default:
            std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
            Sleep(3000);
            exit(1);
        }

        if (KeyAuthApp.response.message.empty()) exit(11);
        if (!KeyAuthApp.response.success)
        {
            std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
            Sleep(1500);
            exit(1);
        }

        if (username.empty() || password.empty())
        {
            WriteToJson(autoLoginFile, "license", key, false, "", "");
            std::cout << skCrypt("License Is Locked For This Device");
        }
        else
        {
            WriteToJson(autoLoginFile, "username", username, true, "password", password);
            std::cout << skCrypt("License Is Locked For This Device");
        }
    }

    std::thread run(checkAuthenticated, ownerid);
    std::thread check(sessionStatus);
    run.detach();
    check.detach();

    std::vector<std::string> targets = {
        "C:\\Program Files\\Maxon Cinema 4D 2024\\corelibs\\c4d_base.xdl64",
        "C:\\Program Files\\Maxon Cinema 4D 2024\\Redshift\\res\\libs\\win64\\redshift-core-vc140.dll",
        "C:\\ProgramData\\redshift\\Tools\\RedshiftLicensingTool.exe",
        "C:\\ProgramData\\redshift\\bin\\altus-cli.exe",
        "C:\\ProgramData\\redshift\\bin\\redshift-core-vc140.dll",
        "C:\\Program Files\\Maxon Cinema 4D 2024\\plugins\\Redshift\\res\\libs\\win64\\redshift-core-vc140.dll"
    };

    for (const auto& path : targets) {
        std::cout << "Patching: " << path << "\n";
        patchFile(path);
    }

    std::cout << "\nDone. Press any key to exit...\n";
    system("pause >nul");
    return 0;
}

bool patchFile(const std::string& filePath) {
    const std::vector<uint8_t> findPattern = {
        0xC7, 0x40, 0x58, 0xDC, 0xFF, 0xFF, 0xFF, 0x33, 0xC0, 0xEB, 0x6D,
        0x44, 0x8B, 0x4C, 0x24, 0x68, 0x45, 0x33, 0xC0, 0x48, 0x8B, 0x54,
        0x24, 0x48, 0x48, 0x8B, 0x4C, 0x24, 0x40, 0xE8
    };

    const std::vector<uint8_t> replacePattern = {
        0xC7, 0x40, 0x58, 0xDC, 0xFF, 0xFF, 0xFF, 0x33, 0xC0, 0xEB, 0x6D,
        0x44, 0x8B, 0x4C, 0x24, 0x68, 0x45, 0x33, 0xC0, 0x48, 0x8B, 0x54,
        0x24, 0x48, 0x48, 0x8B, 0x4C, 0x24, 0x40, 0xB8, 0x00, 0x00, 0x00, 0x00
    };

    std::ifstream in(filePath, std::ios::binary);
    if (!in) {
        std::cerr << "Failed to open: " << filePath << "\n";
        return false;
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(in)), {});
    in.close();

    bool patched = false;
    for (size_t i = 0; i <= buffer.size() - findPattern.size(); ++i) {
        if (std::equal(findPattern.begin(), findPattern.end(), buffer.begin() + i)) {
            std::copy(replacePattern.begin(), replacePattern.end(), buffer.begin() + i);
            patched = true;
            std::cout << "Patched at offset: 0x" << std::hex << i << "\n";
        }
    }

    if (patched) {
        std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        out.close();
        return true;
    }
    else {
        std::cout << "Pattern not found in: " << filePath << "\n";
        return false;
    }
}

void sessionStatus() {
    KeyAuthApp.check(true);
    if (!KeyAuthApp.response.success) {
        exit(0);
    }

    if (KeyAuthApp.response.isPaid) {
        while (true) {
            Sleep(20000);
            KeyAuthApp.check();
            if (!KeyAuthApp.response.success) {
                exit(0);
            }
        }
    }
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);
    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10);
    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;
    localtime_s(&context, &timestamp);
    return context;
}
