# [VCTR](http://datagridsys.com/vctr/) Dashboard

A [Dashing](http://dashing.io) dashboard for [Datagrid](http://datagridsys.com/)'s VCTR service. This uses VCTR's API to display at-a-glance information about your infrastructure, vulnerability status and actionable items to reduce your security risk.

===

This repository provides the necessary widgets, dashboard layout and background jobs needed to produce a dashboard like this:


![Alt](/example.png "Example")


The dashboard runs on top of VCTR's API and requires an existing VCTR account. If you don't have an account yet, you can [sign up](http://www.datagridsys.com/beta-reg) for free or you can [try](https://ace.datagridsys.com/) our anonymous, no registration, nothing to install or download version and check your system for vulnerabilities in a matter of seconds.

===
The following command creates a new container from the standard dashing.io docker image using VCTR's widgets, layout and background jobs.

Use your VCTR API credentials (these will be use both to authenticate browser requests to the dashboard and the background API calls made to the VCTR SaaS).


```
docker run                                                     \
    -d                                                         \
    -p 10013:3030                                              \
    --restart=always                                           \
    -e INTERVAL='30'                                           \
    -e DGRI_USERNAME='changeme'                                \
    -e DGRI_PASSWORD='changeme'                                \
    --name dgri-dashing                                        \
    --hostname dgri-dashing                                    \
    -v=$(pwd)/widgets/dgrinumber/:/widgets/dgrinumber          \
    -v=$(pwd)/widgets/dgrinumber2/:/widgets/dgrinumber2        \
    -v=$(pwd)/widgets/google_treemap/:/widgets/google_treemap  \
    -v=$(pwd)/dashboards:/dashboards                           \
    -v=$(pwd)/jobs:/jobs                                       \
    -v=$(pwd)/config:/config                                   \
    -v=$(pwd)/public/favicon.ico:/public/favicon.ico           \
    frvi/dashing
```
