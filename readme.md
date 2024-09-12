# API Endpoints

## User Management

### Sign Up
- **URL:** `localhost:3800/users/signup`
- **Method:** `POST`
- **Body:**
  ```json
  {
    "firstName": "string",
    "lastName": "string",
    "email": "string",
    "country": "string",
    "password": "string"
  }
  ```
- **Success Response:** 
  - **Code:** 201
  - **Content:** `{ user: { user object }, token: "string" }`

### Sign In
- **URL:** `localhost:3800/users/signin`
- **Method:** `POST`
- **Body:**
  ```json
  {
    "email": "string",
    "password": "string"
  }
  ```
- **Success Response:** 
  - **Code:** 200
  - **Content:** `{ user: { user object }, token: "string" }`

## Campaign Management

### Create a Campaign
- **URL:** `localhost:3800/campaigns`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <token>`
- **Body:**
  ```json
  {
    "email":"string",
    "campaignName": "string",
    "campaignDescription": "string",
    "fundingGoal": "string",
    "category": "string",
    "milestoneTitle": "string",
    "amountNeeded": "string",
    "completionDate": "date",
    "teamInformation": "string",
    "expectedImpact": "string",
    "risksAndChalllenges": "string"
  }
  ```
- **Success Response:** 
  - **Code:** 201
  - **Content:** `{ campaign object }`

### Get All Campaigns
- **URL:** `localhost:3800/campaigns`
- **Method:** `GET`
- **Success Response:** 
  - **Code:** 200
  - **Content:** `[{ campaign objects }]`

### Get a Specific Campaign
- **URL:** `localhost:3800/campaigns/:id`
- **Method:** `GET`
- **Success Response:** 
  - **Code:** 200
  - **Content:** `{ campaign object }`

### Update a Campaign
- **URL:** `localhost:3800/campaigns/:id`
- **Method:** `PATCH`
- **Headers:** `Authorization: Bearer <token>`
- **Body:** `{ fields to update }`
- **Success Response:** 
  - **Code:** 200
  - **Content:** `{ updated campaign object }`

### Delete a Campaign
- **URL:** `localhost:3800/campaigns/:id`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <token>`
- **Success Response:** 
  - **Code:** 200
  - **Content:** `{ deleted campaign object }`

### Get User's Campaigns
- **URL:** `localhost:3800/user/campaigns`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <token>`
- **Success Response:** 
  - **Code:** 200
  - **Content:** `[{ campaign objects }]`
