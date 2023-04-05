# tlspk-helper

```
# on MacOS
brew install fsevents-tools

while true
  do notifywait ./tlspk-helper.sh
  echo "uploading tlspk-helper.sh"
  aws s3 cp tlspk-helper.sh s3://venafi-tlspk/tlspk-helper.sh
done
```
