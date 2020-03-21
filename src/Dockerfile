FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build
ADD . /src
WORKDIR /src

RUN dotnet restore CO2_CORE_DLL_NETCORE/CO2_CORE_DLL_NETCORE.csproj

COPY . .
RUN dotnet publish CO2_CORE_DLL_NETCORE/CO2_CORE_DLL_NETCORE.csproj -c Release -o out

FROM mcr.microsoft.com/dotnet/core/runtime:3.1 AS runtime
WORKDIR .
COPY --from=build ./out /src/DOCKER_BUILD