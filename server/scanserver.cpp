/*
AirSane Imaging Daemon
Copyright (C) 2018 Simul Piscator

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "scanserver.h"

#include <fstream>
#include <sstream>
#include <csignal>
#include <cstring>
#include <algorithm>

#include "scanner.h"
#include "scanjob.h"
#include "basic/xml.h"
#include "zeroconf/hotplugnotifier.h"

ScanServer::ScanServer(int argc, char** argv)
    : mDoRun(true), mHotplug(true), mAnnounce(true), mLocalonly(true)
{
    std::string port, interface, accesslog, hotplug, announce, localonly, debug, cross_origin;
    struct { const std::string name, def, info; std::string& value; } options[] = {
    { "listen-port", "8090", "listening port", port },
    { "interface", "", "listen on named interface only", interface },
    { "access-log", "", "HTTP access log, - for stdout", accesslog },
    { "cross-origin", "", "address to enable cross origin access for", cross_origin },
    { "hotplug", "true", "reload scanner list on hotplug event", hotplug },
    { "mdns-announce", "true", "announce scanners via mDNS (avahi)", announce },
    { "local-scanners-only", "true", "ignore SANE network scanners", localonly },
    { "debug", "false", "log debug information to stderr", debug },
    };
    for(auto& opt : options)
        opt.value = opt.def;
    bool help = false;
    for(int i = 1; i < argc; ++i) {
        std::string option = argv[i];
        bool found = false;
        for(auto& opt : options) {
            if(option.find("--" + opt.name + "=") == 0) {
                found = true;
                opt.value = option.substr(option.find('=') + 1);
                break;
            } else if(option == "--" + opt.name) {
                found = true;
                help = true;
                std::cerr << "missing argument for option " << option << std::endl;
                break;
            }
        }
        if(!found) {
            help = true;
            if(option != "--help")
                std::cerr << "unknown option: " << option << std::endl;
        }
    }

    if(debug != "true")
        std::clog.rdbuf(nullptr);
    sanecpp::log.rdbuf(std::clog.rdbuf());

    mCrossOrigin = "";
    if (!cross_origin.empty()) {
        mCrossOrigin = cross_origin;
    }

    mHotplug = (hotplug == "true");
    mAnnounce = (announce == "true");
    mLocalonly = (localonly == "true");

    uint16_t port_ = 0;
    if(!(std::istringstream(port) >> port_)) {
        std::cerr << "invalid port number: " << port << std::endl;
        mDoRun = false;
    }
    if(help) {
        std::cout << "options, and their defaults, are:\n";
        for(auto& opt : options)
            std::cout << " --" << opt.name << "=" << opt.def << "\t" << opt.info << "\n";
        std::cout << " --help\t" << "show this help" << std::endl;
        mDoRun = false;
    }
    if(mDoRun) {
        if(!interface.empty())
            setInterfaceName(interface);
        setPort(port_);
        if(accesslog.empty())
            std::cout.rdbuf(nullptr);
        else if(accesslog != "-")
            std::cout.rdbuf(mLogfile.open(accesslog, std::ios::app));
    }
}

bool ScanServer::run()
{
    if(!mDoRun)
        return false;

    struct Notifier : HotplugNotifier
    {
        ScanServer& server;
        Notifier(ScanServer& s) : server(s) {}
        void onHotplugEvent(Event ev) override
        {
            switch(ev) {
            case deviceArrived:
            case deviceLeft:
                std::clog << "hotplug event, reloading configuration" << std::endl;
                server.terminate(SIGHUP);
                break;
            }
        }
    };
    std::shared_ptr<Notifier> pNotifier;
    if(mHotplug)
        pNotifier = std::make_shared<Notifier>(*this);

    bool ok = false, done = false;
    do {
        std::clog << "enumerating " << (mLocalonly ? "local " : " ") << "devices..." << std::endl;
        auto scanners = sanecpp::enumerate_devices(mLocalonly);
        for(const auto& s : scanners) {
            std::clog << "found: " << s.name << " (" << s.vendor << " " << s.model << ")" << std::endl;
            auto pScanner = std::make_shared<Scanner>(s);
            if(pScanner->error())
                std::clog << "error: " << pScanner->error() << std::endl;
            else
                std::clog << "uuid: " << pScanner->uuid() << std::endl;
            std::shared_ptr<MdnsPublisher::Service> pService;
            if(mAnnounce && !pScanner->error())
            {
                pService = std::make_shared<MdnsPublisher::Service>(&mPublisher);
                pService->setType("_uscan._tcp.").setName(pScanner->makeAndModel());
                pService->setInterfaceIndex(interfaceIndex()).setPort(port());
                pService->setTxt("txtvers", "1");
                pService->setTxt("vers", "2.0");
                std::string s;
                for(const auto f : pScanner->documentFormats())
                    s += "," + f;
                if(!s.empty())
                  pService->setTxt("pdl", s.substr(1));
                pService->setTxt("ty", pScanner->makeAndModel());
                pService->setTxt("uuid", pScanner->uuid());
                pService->setTxt("rs", pScanner->uri().substr(1));
                s.clear();
                for(const auto cs : pScanner->colorSpaces())
                    s += "," + cs;
                if(!s.empty())
                  pService->setTxt("cs", s.substr(1));
                s.clear();
                if(pScanner->hasPlaten())
                    s += ",platen";
                if(pScanner->hasAdf())
                    s += ",adf";
                if(!s.empty())
                  pService->setTxt("is", s.substr(1));
                pService->setTxt("duplex", pScanner->hasDuplexAdf() ? "T" : "F");

                if(!pService->announce())
                    pService.reset();
                if(pService)
                    std::clog << "published as '" << pService->name() << "'" << std::endl;
            }
            mScanners.push_back(std::make_pair(pScanner, pService));
        }
        ok = HttpServer::run();
        mScanners.clear();
        if(ok && terminationStatus() == SIGHUP) {
            std::clog << "received SIGHUP, reloading" << std::endl;
        } else if(ok && terminationStatus() == SIGTERM) {
            std::clog << "received SIGTERM, exiting" << std::endl;
            done = true;
        } else {
            ok = false, done = true;
        }
    } while(!done);
    if(ok) {
        std::clog << "finished ok" << std::endl;
    } else {
        std::cerr << "finished with error "
                  << terminationStatus() << ": "
                  << ::strerror(terminationStatus())
                  << std::endl;
    }
    return ok;
}

void ScanServer::writeServerXML(std::ostream& os) {
    os <<
       "<?xml version='1.0' encoding='UTF-8'?>\r\n"
       "<airsane:Server"
       " xmlns:airsane='http://heliumnet.nl/schemas/airsane/2019/08'"
       " xmlns:pwg='http://www.pwg.org/schemas/2010/12/sm'"
       " xmlns:scan='http://schemas.hp.com/imaging/escl/2011/05/03'>\r\n";
    os << "<airsane:Version>\r\n";
    os << "<airsane:Date>" << __DATE__ << "</airsane:Date>\r\n";
    os << "<airsane:Time>" << __TIME__ << "</airsane:Time>\r\n";
    os << "<airsane:CommitHash>" << GIT_COMMIT_HASH << "</airsane:CommitHash>\r\n";
    os << "<airsane:Branch>" << GIT_BRANCH << "</airsane:Branch>\r\n";
    os << "<airsane:Revision>" << GIT_REVISION_NUMBER << "</airsane:Revision>\r\n";
    os << "</airsane:Version>\r\n";
    os << "<airsane:Devices>\r\n";
    for(const auto& s : mScanners) {
        os << "<airsane:Device>\r\n";
        os << "<pwg:Version>2.0</pwg:Version>\r\n";
        os << "<pwg:MakeAndModel>" << xmlEscape(s.first->makeAndModel()) << "</pwg:MakeAndModel>\r\n";
        os << "<scan:UUID>" << xmlEscape(s.first->uuid()) << "</scan:UUID>\r\n";
        os << "<airsane:Uri>" << xmlEscape(s.first->uri()) << "</airsane:Uri>\r\n";
        if (s.second) {
            os << "<airsane:Name>" << xmlEscape(s.first->makeAndModel()) << "</airsane:Name>\r\n";
        }
        os << "</airsane:Device>\r\n";
    }
    os << "</airsane:Devices>\r\n";
    os << "</airsane:Server>\r\n";
}

void ScanServer::onRequest(const Request& request, Response& response)
{
    if(request.uri() == "/" && request.method() == HttpServer::HTTP_GET){
        response.setStatus(HttpServer::HTTP_OK);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        response.setHeader(HttpServer::HTTP_HEADER_CONTENT_TYPE, "text/xml");
        writeServerXML(response.send());
        return;
    } else if(request.uri() == "/" && request.method() == HttpServer::HTTP_OPTIONS) {
        response.setStatus(HttpServer::HTTP_NO_CONTENT);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, "GET");
        response.send();
        return;
    } else if(request.uri() == "/reset" && request.method() == HttpServer::HTTP_POST) {
        response.setStatus(HttpServer::HTTP_OK);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        response.send();
        this->terminate(SIGHUP);
        return;
    } else if(request.uri() == "/reset" && request.method() == HttpServer::HTTP_OPTIONS) {
        response.setStatus(HttpServer::HTTP_NO_CONTENT);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, "POST");
        response.send();
        return;
    }
    for(auto& s : mScanners) {
        if(request.uri().find(s.first->uri()) == 0) {
            handleScannerRequest(s, request, response);
            return;
        }
    }
    HttpServer::onRequest(request, response);
}

static bool clientIsAirscan(const HttpServer::Request& req)
{
    return req.header(HttpServer::HTTP_HEADER_USER_AGENT).find("AirScanScanner") != std::string::npos;
}

void ScanServer::handleScannerRequest(ScannerList::value_type& s, const HttpServer::Request &request, HttpServer::Response &response)
{
    response.setStatus(HttpServer::HTTP_OK);
    std::string res = request.uri().substr(s.first->uri().length());
    if((res.empty() || res == "/") && request.method() == HttpServer::HTTP_GET) {
        response.setHeader(HttpServer::HTTP_HEADER_CONTENT_TYPE, "text/xml");
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        s.first->writeScannerStatusXml(response.send());
        return;
    } else if((res.empty() || res == "/") && request.method() == HttpServer::HTTP_OPTIONS) {
        response.setStatus(HttpServer::HTTP_NO_CONTENT);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, "GET");
        response.send();
        return;
    } else if(res == "/ScannerCapabilities" && request.method() == HttpServer::HTTP_GET) {
        response.setHeader(HttpServer::HTTP_HEADER_CONTENT_TYPE, "text/xml");
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        s.first->writeScannerCapabilitiesXml(response.send());
        return;
    } else if(res == "/ScannerCapabilities" && request.method() == HttpServer::HTTP_OPTIONS) {
        response.setStatus(HttpServer::HTTP_NO_CONTENT);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, "GET");
        response.send();
    } else if(res == "/ScannerStatus" && request.method() == HttpServer::HTTP_GET) {
        response.setHeader(HttpServer::HTTP_HEADER_CONTENT_TYPE, "text/xml");
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        s.first->writeScannerStatusXml(response.send());
        return;
    } else if(res == "/ScannerStatus" && request.method() == HttpServer::HTTP_OPTIONS) {
        response.setStatus(HttpServer::HTTP_NO_CONTENT);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, "GET");
        response.send();
        return;
    }
    const std::string ScanJobsDir = "/ScanJobs";
    if(res == ScanJobsDir && request.method() == HttpServer::HTTP_POST) {
        bool autoselectFormat = clientIsAirscan(request);
        std::shared_ptr<ScanJob> job = s.first->createJobFromScanSettingsXml(request.content(), autoselectFormat);
        if(job) {
            response.setStatus(HttpServer::HTTP_CREATED);
            response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
            response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS, HttpServer::HTTP_HEADER_LOCATION);
            response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS, HttpServer::HTTP_HEADER_LOCATION);
            response.setHeader(HttpServer::HTTP_HEADER_LOCATION, job->uri());
            response.send();
            return;
        }
    } else if(res == ScanJobsDir && request.method() == HttpServer::HTTP_OPTIONS) {
        response.setStatus(HttpServer::HTTP_NO_CONTENT);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, "POST");
        response.send();
        return;
    }
    if(res.find(ScanJobsDir) != 0)
        return;
    res = res.substr(ScanJobsDir.length());
    if(res.empty() || res.front() != '/')
        return;
    res = res.substr(1);
    size_t pos = res.find('/');
    auto job = s.first->getJob(res.substr(0, pos));
    if (job == nullptr)
        return;
    if(pos > res.length() && request.method() == HttpServer::HTTP_OPTIONS) {
        response.setStatus(HttpServer::HTTP_NO_CONTENT);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, "DELETE");
        response.send();
        return;
    } else if(pos > res.length() && request.method() == HttpServer::HTTP_DELETE && s.first->cancelJob(res)) {
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        response.send();
        return;
    } else if(res.substr(pos) == "/NextDocument" && request.method() == HttpServer::HTTP_GET) {
        auto job = s.first->getJob(res.substr(0, pos));
        if(job->isFinished()) {
            response.setStatus(HttpServer::HTTP_NOT_FOUND);
            response.send();
        } else {
            if(job->beginTransfer()) {
                response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
                response.setHeader(HttpServer::HTTP_HEADER_CONTENT_TYPE, job->documentFormat());
                response.setHeader(HttpServer::HTTP_HEADER_TRANSFER_ENCODING, "chunked");
                job->finishTransfer(response.send());
            } else {
                job->abortTransfer();
                response.setStatus(HttpServer::HTTP_SERVICE_UNAVAILABLE);
                response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
                response.send();
            }
        }
        return;
    } else if(res.substr(pos) == "/NextDocument" && request.method() == HttpServer::HTTP_OPTIONS) {
        response.setStatus(HttpServer::HTTP_NO_CONTENT);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, mCrossOrigin);
        response.setHeader(HttpServer::HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, "GET");
        response.send();
        return;
    }
}

