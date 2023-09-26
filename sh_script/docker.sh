#!/bin/bash
set -e

FOLDER=""

usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
  -d <docker file>     Path of Dockerfile.
EOM
}

error() {
    echo -e "\e[1;31mERROR: $*\e[0;0m"
    exit 1
}

process_args() {
    while getopts ":f:h" option; do
        case "$option" in
            f) FOLDER=$OPTARG;;
            h) usage
               exit 0
               ;;
            *)
               echo "Invalid option '-$OPTARG'"
               usage
               exit 1
               ;;
        esac
    done

    if [[ -z ${FOLDER} ]]; then
        error "Please specify the folder of where the Dockerfile is located through -f."
    fi

    if [[ ! -f "${FOLDER}/Dockerfile" ]]; then
        error "Dockerfile does not exist."
    fi
}

process_args $@

pushd ${FOLDER}

# If the docker image does not exist, build the docker image
set +e && docker image inspect tdshim.build.env:latest > /dev/null 2>&1 && set -e
if [ $? != 0 ]; then
    docker build -t tdshim.build.env \
            --build-arg https_proxy=$https_proxy \
            --build-arg http_proxy=$http_proxy \
            .
fi

popd

# Run the docker image
docker run -it --rm tdshim.build.env
