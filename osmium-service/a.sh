#!/bin/bash

curl -X POST localhost:3000/4deb433c53cf800d0ba1501e416569902ac41d04f5587b2aed8e34ed35ebc512 -H "Content-Type: application/json" --data-binary @- <<DATA
{
  "Id": 12345,
  "Customer": "John Smith",
  "Quantity": 1,
  "Price": 10.00
}
DATA