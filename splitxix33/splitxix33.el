;; splitxix33: a splitmix64 with memorable constants -*- lexical-binding: t; -*-
;; This is free and unencumbered software released into the public domain.

(defun splitxix33 (seed)
  (let ((s seed))
    (lambda ()
      (let ((r (setf s (logand #xffffffffffffffff (+ s 1111111111111111111)))))
        (setf r (logxor r (lsh r -33))
              r (logand #xffffffffffffffff (* r 1111111111111111111))
              r (logxor r (lsh r -33))
              r (logand #xffffffffffffffff (* r 1111111111111111111))
              r (logxor r (lsh r -33)))))))


;; Example
(let ((a (splitxix33 0)) (b (splitxix33 1))
      (c (splitxix33 2)) (d (splitxix33 3)))
  (dotimes (_ 40)
    (princ (format "%016x %016x %016x %016x\n"
                   (funcall a) (funcall b) (funcall c) (funcall d)))))
