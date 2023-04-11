# tlspk-helper

```
# on MacOS
brew install fsevents-tools

while true
  do notifywait ./tlspk-helper.sh
  echo "uploading tlspk-helper.sh"
  aws s3 cp tlspk-helper.sh s3://venafi-ecosystem-dev/tlspk # drop the "-dev" as appropriate 
done
```

Invoke as follows:
```
curl -fsSL -o tlspk-helper.sh https://venafi-ecosystem.s3.us-east-1.amazonaws.com/tlspk/tlspk-helper.sh && chmod 700 tlspk-helper.sh
./tlspk-helper.sh
```
