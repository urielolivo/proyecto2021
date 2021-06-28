FROM python:3.9


COPY ./requirement.txt /tmp
RUN pip install -r /tmp/requirement.txt

ENV llave=""
ENV dbname=""
ENV dbuser=""
ENV pwdbd=""
ENV dbhost=""
ENV dbort="3306"

RUN mkdir /code
RUN mkdir /start

COPY ./run.sh  /start


WORKDIR /code

RUN chmod +x /start/run.sh
RUN useradd cobi -s /bin/bash
RUN chown -R cobi /code
RUN chown -R cobi /start

USER cobi

CMD /start/run.sh


