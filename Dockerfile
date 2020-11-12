FROM python:slim

LABEL maintainer="Jay Chen <jaychen@paloaltonetworks.com>"

RUN useradd --create-home --shell /bin/bash iamuser

ENV PATH="/home/iamuser/.local/bin:${PATH}" 

USER iamuser

WORKDIR /home/iamuser

COPY *.py *.txt *. *.md LICENSE ./

COPY ./aws_svc/*.py ./aws_svc/

COPY ./config_dir/*.txt ./config_dir/config.json ./config_dir/

VOLUME [ "/home/iamuser/config_dir/" ]

RUN pip3 install -r requirements.txt

ENTRYPOINT [ "python3", "iamfinder.py" ]

CMD ["-h"]