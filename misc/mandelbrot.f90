! Mandelbrot set renderer in Fortran 2003
!   $ gfortran -std=f2003 -O3 -ffast-math mandelbrot.f90
!   $ ./a.out >mandelbrot.pgm
program mandelbrot
    implicit none

    real, parameter :: xmin = -2.5, xmax = +1.5
    real, parameter :: ymin = -1.5, ymax = +1.5
    real, parameter :: step = 0.0025
    integer, parameter :: width  = int((xmax - xmin) / step)
    integer, parameter :: height = int((ymax - ymin) / step)
    integer, parameter :: iterations = 255

    integer :: i, x, y
    integer, allocatable :: k(:, :)
    complex, allocatable :: z(:, :)
    complex, allocatable :: c(:, :)

    allocate(k(width, height))
    k = 0
    allocate(z(width, height))
    z = 0
    allocate(c(width, height))
    forall (x = 1:width, y = 1:height)
        c(x, y) = cmplx((x - 1)*step + xmin, (y - 1)*step + ymin)
    end forall

    ! Compute the Mandelbrot set
    do i = 1, iterations
        z = z**2 + c
        where (abs(z) < 2) k = k + 1
    end do

    ! Render Netpbm grayscale image
    print '(a/2i10/i4)', 'P2', width, height, iterations
    print *, int(((real(k) / iterations) ** 0.5) * iterations)
end program
