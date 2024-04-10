// Copyright (c) 2020 ElephantSe4l. All Rights Reserved.
// Released under MPL-2.0, see LICENCE for more information.

#ifndef FRESHYCALLS_UTILS_HPP_
#define FRESHYCALLS_UTILS_HPP_

#include <Windows.h>
#include <string>
#include <cstdint>
#include <stdexcept>

#define SEED 0xD8
namespace calls::utils {

// Tries to get the error message associated to `error_code` using `FormatMessageA`. Returns
// a string containing the message.

std::string GetErrorMessage(uint32_t error_code, bool is_ntstatus = false);


// Tries to format a string using `snprintf`. Returns the formatted string.
// WARNING: Be aware this function is REALLY bug prone as it takes a message template with n arguments and passes it
// directly to `snprintf`. Does not make any kind of check.

template<typename... FormatArgs>
std::string FormatString(std::string_view string_template, FormatArgs... format_args) {
  const size_t string_size = snprintf(nullptr, 0, string_template.data(), std::forward<FormatArgs>(format_args)...);
  if (string_size <= 0) {
    throw std::runtime_error("[sisyphus::utils::FormatString] Formatted string size is negative or 0.");
  }

  auto formatted_string = new char[string_size + 1];
  snprintf(formatted_string, string_size + 1, string_template.data(), std::forward<FormatArgs>(format_args)...);

  return std::string(formatted_string);
}


//https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringRotr32.cpp

inline UINT32 _HashStringRotr32SubA(UINT32 Value, UINT Count) {

    DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
    Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
    return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop )
}

inline SIZE_T _StrlenA(LPCSTR String) {

    LPCSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

//String HASH
inline DWORD _HashStringRotr32A(PCHAR String) {

    DWORD Value = 0;

    for (INT Index = 0; Index < _StrlenA(String); Index++)
        Value = String[Index] + _HashStringRotr32SubA(Value, SEED);

    return Value;
}
}
#endif