#!/bin/bash

gcloud -q --project=aqueous-choir-160420 app deploy --version 1 3>> upload_log.txt
