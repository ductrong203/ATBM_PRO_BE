1. tạo db "atbm_db"
2. sửa file appsettings.json
   "ConnectionStrings": {
   "DefaultConnection": "server=localhost;database=atbm_db;user=root;password=password của bạn"
   },
3. dotnet tool install --global dotnet-ef
4. chạy dòng : "dotnet ef database update"
