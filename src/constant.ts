export const providers = {
  database: 'DATABASE_CONNECTION',
  user: 'USER_MODEL',
  cart: 'CART_MODEL',
  menu: 'MENU_MODEL',
};

export const jwtConstant = {
  secret: 'most valued secret',
};

export const SOCIAL_SDK_URLS = {
  facebook:
    'https://graph.facebook.com/v16.0/me?fields=id,name,first_name,last_name,middle_name,email,picture{height,url,width}&access_token=',
  google: 'https://www.googleapis.com/oauth2/v3/userinfo?access_token=',
};
