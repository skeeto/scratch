;; Middle Multiplicative Lagged Fibonacci PRNG -*- lexical-binding: t; -*-
;; This is free and unencumbered software released into the public domain.

(defun mmlfg (seed)
  "Returns a closure that generates a 64-bit result each invocation."
  (let ((state (make-vector 15 0))
        (i 14)
        (j 12))
    (dotimes (k 15)
      (setf seed (logand (+ (* seed #x3243f6a8885a308d)
                            1111111111111111111)
                         #xffffffffffffffff)
            (aref state k) (logior 1 (logxor seed (lsh seed -31)))))
    (lambda ()
      (let ((r (* (aref state i) (aref state j))))
        (prog1 (logand (lsh r -32) #xffffffffffffffff)
          (setf (aref state i) (logand r #xffffffffffffffff)
                i (% (+ i 14) 15)
                j (% (+ j 14) 15)))))))


;; Example
(let ((a (mmlfg 0)) (b (mmlfg 1)) (c (mmlfg 2)) (d (mmlfg 3)))
  (dotimes (_ 40)
    (princ (format "%016x %016x %016x %016x\n"
                   (funcall a) (funcall b) (funcall c) (funcall d)))))
