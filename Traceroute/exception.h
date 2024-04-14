#pragma once

#include <iostream>
#include <exception>

class LocalException : public std::exception
{
    std::string exceptionInfo = "\nTracing route aborted\n";

public:
    LocalException() : exceptionInfo("\nTracing route aborted\n"){};
    LocalException(std::string exceptionInfo)
    {
        this->exceptionInfo = exceptionInfo + this->exceptionInfo;
    };
    const char *what() const noexcept override
    {
        return exceptionInfo.c_str();
    }
};