FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|docker.com/linux/debian|docker.com/linux/ubuntu|g' /etc/apt/sources.list
RUN apt update -y
RUN apt install python3 python3-pip git wget -y

# Install google chrome
RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN apt install ./google-chrome-stable_current_amd64.deb  -y

RUN mkdir /app
WORKDIR /app

# Install Astellar
RUN git clone https://github.com/capstone-design-1/Astellar
WORKDIR /app/Astellar
RUN pip3 install -r requirements.txt

EXPOSE 8081

CMD python3 app.py