BAB 6. KESIMPULAN

6.1 Kesimpulan

Penelitian ini telah berhasil mengembangkan sistem Secure Financial Report Sharing yang memenuhi tujuan awal untuk menciptakan platform berbagi dokumen finansial yang aman dan efisien. Sistem yang dibangun menerapkan multiple algoritma enkripsi (AES-256, DES, dan RC4) dengan pendekatan keamanan berlapis.

6.1.1 Pencapaian Tujuan Penelitian

Sistem berhasil mengimplementasikan tiga aspek utama yang menjadi fokus penelitian:

Pertama, implementasi multi-algoritma enkripsi berjalan dengan baik. AES-256 memberikan keamanan tertinggi dengan throughput 214.7 MB/s, RC4 menunjukkan performa terbaik pada 970 MB/s, sementara DES tetap berfungsi untuk keperluan kompatibilitas dengan throughput 74.9 MB/s.

Kedua, sistem keamanan berlapis telah terbukti efektif. Pengujian komprehensif menunjukkan tidak ditemukan vulnerability critical pada serangan SQL injection, XSS, maupun file upload attacks. Sistem juga dilengkapi dengan session management yang aman dan access control yang ketat.

Ketiga, performa sistem tetap terjaga meskipun menerapkan multiple layer security. CPU usage maksimal hanya 38.6% dan mampu menangani 850+ operasi per detik dengan 8 concurrent threads.

6.1.2 Hasil Pengujian

Pengujian dilakukan dalam tiga kategori utama dengan hasil sebagai berikut:

Pengujian fungsionalitas menunjukkan hasil sempurna dengan 16 dari 16 test cases berhasil. Semua fitur utama seperti registrasi user, upload file, sharing antar user, dan download berjalan sesuai ekspektasi.

Pengujian keamanan menghasilkan zero critical vulnerabilities dari berbagai attack vectors yang diuji. Sistem terbukti resistant terhadap common web vulnerabilities dan memenuhi standar OWASP Top 10.

Pengujian performa menunjukkan rating "Good" dengan throughput encryption yang memadai untuk penggunaan enterprise. Sistem juga menunjukkan scalability yang baik hingga multiple concurrent users.

6.1.3 Kontribusi Penelitian

Penelitian ini memberikan beberapa kontribusi praktis dan akademis:

Dari sisi teknis, dikembangkan framework enkripsi yang fleksibel yang dapat mengakomodasi multiple algorithms berdasarkan kebutuhan performa dan keamanan. Selain itu, dibuat metodologi testing keamanan yang comprehensive untuk aplikasi web.

Dari sisi akademis, penelitian ini menyediakan studi perbandingan performa algoritma enkripsi dalam konteks aplikasi web real-world, serta dokumentasi lengkap implementasi security best practices.

6.1.4 Validasi Hipotesis

Ketiga hipotesis awal penelitian telah terbukti:

Hipotesis pertama tentang peningkatan fleksibilitas melalui multi-algoritma enkripsi terbukti dengan tersedianya pilihan algoritma sesuai kebutuhan spesifik (security vs performance).

Hipotesis kedua mengenai efektivitas keamanan berlapis terbukti dengan hasil pengujian yang menunjukkan zero vulnerabilities dari comprehensive security testing.

Hipotesis ketiga tentang maintenance performa tinggi dengan implementasi security yang ketat terbukti dengan achievement performance rating "Good" tanpa mengorbankan aspek keamanan.

6.2 Saran Untuk Pengembangan Selanjutnya

Berdasarkan hasil implementasi dan testing, beberapa area dapat dikembangkan lebih lanjut:

6.2.1 Peningkatan Keamanan

Implementasi two-factor authentication akan meningkatkan security layer. Penelitian terhadap post-quantum cryptography juga perlu dipertimbangkan mengingat perkembangan teknologi quantum computing.

Hardware Security Module (HSM) integration dapat dipertimbangkan untuk environment dengan requirement keamanan yang sangat tinggi.

6.2.2 Optimasi Performa

Implementasi hardware acceleration seperti Intel AES-NI dapat meningkatkan throughput encryption secara signifikan. Parallel processing untuk file besar juga dapat dioptimalkan.

Database optimization melalui indexing strategy dan connection pooling akan meningkatkan response time secara keseluruhan.

6.2.3 Fitur Tambahan

Version control system untuk file akan memberikan nilai tambah untuk collaborative work environment. Integration dengan productivity tools seperti Office 365 juga akan meningkatkan user adoption.

Mobile application development dapat memperluas jangkauan penggunaan sistem.

6.2.4 Compliance dan Governance

Implementasi compliance framework untuk regulasi seperti GDPR dan SOX akan membuat sistem lebih suitable untuk deployment enterprise yang sesungguhnya.

Automated audit trail dan reporting capabilities juga akan membantu dalam memenuhi regulatory requirements.

6.2.5 Monitoring dan Analytics

Real-time monitoring system dan usage analytics akan membantu dalam maintenance dan optimization sistem. Predictive analytics untuk capacity planning juga dapat diimplementasikan.

6.2.6 Roadmap Implementasi

Pengembangan dapat dilakukan dalam beberapa fase:

Fase 1 (0-6 bulan): Focus pada security enhancements dan performance optimization
Fase 2 (6-12 bulan): Feature expansion dan mobile development  
Fase 3 (12-18 bulan): Enterprise integration dan compliance automation
Fase 4 (18-24 bulan): Advanced features seperti AI integration dan blockchain implementation

Implementasi bertahap ini akan memastikan sistem tetap stable sambil terus berkembang sesuai kebutuhan user dan perkembangan teknologi.

Penelitian ini telah berhasil mencapai semua objectives yang ditetapkan dan menghasilkan sistem yang ready untuk production deployment. Kontribusi baik dari sisi akademis maupun praktis diharapkan dapat memberikan manfaat untuk pengembangan sistem serupa di masa depan.