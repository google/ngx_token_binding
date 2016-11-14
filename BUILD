# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

licenses(["notice"])  # Apache 2.0

exports_files(["LICENSE"])

load("@nginx//:build.bzl", "nginx_copts")

cc_library(
    name = "token_binding",
    srcs = [
        "src/ngx_token_binding_module.c",
    ],
    hdrs = [
        "src/ngx_token_binding_module.h",
    ],
    copts = nginx_copts,
    defines = [
        "NGX_TOKEN_BINDING",
    ],
    includes = [
        "src",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "@nginx//:core",
        "@token_bind//:token_bind",
    ],
)

cc_library(
    name = "http_token_binding",
    srcs = [
        "src/ngx_http_token_binding_module.c",
    ],
    copts = nginx_copts,
    defines = [
        "NGX_HTTP_TOKEN_BINDING",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        ":token_binding",
        "@nginx//:core",
        "@nginx//:http",
    ],
)
