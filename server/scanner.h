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

#ifndef SCANNER_H
#define SCANNER_H

#include <iostream>
#include <string>
#include <memory>

#include "sanecpp/sanecpp.h"

class ScanJob;

class Scanner
{
public:
    Scanner(const sanecpp::device_info&);
    ~Scanner();
    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;

    const char* error() const;
    std::string statusString() const;

    const std::string& uuid() const;
    const std::string& uri() const;
    const std::string& makeAndModel() const;

    const std::vector<std::string>& documentFormats() const;
    const std::vector<std::string>& colorSpaces() const;
    const std::vector<std::string>& colorModes() const;
    const std::vector<std::string>& supportedIntents() const;
    const std::vector<std::string>& inputSources() const;

    int minResDpi() const;
    int maxResDpi() const;
    int maxWidthPx300dpi() const;
    int maxHeightPx300dpi() const;

    bool hasPlaten() const;
    bool hasAdf() const;
    bool hasDuplexAdf() const;
    std::string platenSourceName() const;
    std::string adfSourceName() const;

    std::shared_ptr<ScanJob> createJobFromScanSettingsXml(const std::string&, bool autoselectFormat = false);
    std::shared_ptr<ScanJob> getJob(const std::string& uuid);
    bool cancelJob(const std::string&);
    int purgeJobs(int maxAgeSeconds);
    typedef std::vector<std::shared_ptr<ScanJob>> JobList;
    JobList jobs() const;

    std::shared_ptr<sanecpp::session> open();
    bool isOpen() const;

    void writeScannerCapabilitiesXml(std::ostream&) const;
    void writeScannerStatusXml(std::ostream&) const;

private:
    struct Private;
    Private* p;
};

#endif // SCANNER_H
