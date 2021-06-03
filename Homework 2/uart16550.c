// SPDX-License-Identifier: GPL-2.0+

/*
 * uart16550.c - Linux UART driver
 *
 * Author: Călin Jugănaru   <calin_vlad.juganaru@stud.acs.upb.ro>
 * Author: Cezar Crăciunoiu <cezar.craciunoiu@gmail.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/cdev.h>
#include <linux/io.h>
#include <linux/kfifo.h>

#include "./uart16550.h"

/* Registru de activare al întreruperilor */
#define IER(baseport)		((baseport) + 0b001)
/* Registru de identificare al întreruperilor */
#define IIR(baseport)		((baseport) + 0b010)
/* Registru de control al cozilor */
#define FCR(baseport)		((baseport) + 0b010)
/* Registru de control al linie */
#define LCR(baseport)		((baseport) + 0b011)
/* Registru de control al modem-ului */
#define MCR(baseport)		((baseport) + 0b100)
/* Registru de stare a liniei */
#define LSR(baseport)		((baseport) + 0b101)

/* Verificări pentru întreruperi de citire sau scriere */
#define IIR_NEW_READ(baseport)	((baseport) & 0b100)
#define IIR_NEW_WRITE(baseport)	((baseport) & 0b010)

/* Activarea și dezactivarea întreruperilor de citire și scriere */
#define IER_READ	0b00000001
#define IER_WRITE	0b00000010

/* Activarea pauzelor */
#define BREN		0b01000000
/* Bit de acces la zăvorul divizorului */
#define DLAB		0b10000000

/* Activarea întreruperii pentru date noi primite */
#define ERDAI		0b00000001
/* Linia de venire a întreruperilor */
#define OUT_LINE	0b00000100
/* Opțiuni pentru configurarea cozii */
#define FIFO_OPTS	0b11000111

/* Date dispozitiv */
#define DEVICE_BUF_SZ	8192
#define MODULE_NAME	"uart16550"
#define MINOR_COM1	0
#define MINOR_COM2	1

/* Configurații linii de date și întreruperi */
#define COM1_BASEPORT	0x3F8
#define COM1_IRQ        4
#define COM2_BASEPORT	0x2F8
#define COM2_IRQ        3
#define COM_NR_PORTS	8
#define COM_DATA_SIZE	14

#define minors_offset (minors == MAX_NUMBER_DEVICES ? 0 : minor[MINOR_COM2])

/* Spațiul de stocare al parametrilor */
static int major = 42;
static int option = OPTION_BOTH;

module_param(major, int, 0);
MODULE_PARM_DESC(major, "Major of the device");
module_param(option, int, 0);
MODULE_PARM_DESC(option, "OPTION_BOTH = 3, OPTION_COM1 = 1, OPTION_COM2 = 2");

/*
 * struct struct uart_device - șablonul unui dispozitiv UART
 *
 * @chrdev:		dispozitivul caracter
 *
 * @read_count:		numărul de octeți citiți
 * @read_done:		indicator al terminării citirii
 * @read_queue:		coada de așteptare a datelor de citit
 *
 * @write_count:	numărul de octeți scriși
 * @write_done:		indicator al terminării scrierii
 * @write_queue:	coada de așteptare a datelor de scris
 *
 * @baseport:		adresa de bază a dispozitivului
 * @read_fifo:		coada FIFO pentru citire
 * @write_fifo:		coada FIFO pentru scriere
 */
struct uart_device {
	struct cdev chrdev;

	int read_count;
	atomic_t read_done;
	wait_queue_head_t read_queue;

	int write_count;
	atomic_t write_done;
	wait_queue_head_t write_queue;

	int baseport;
	DECLARE_KFIFO(read_fifo, u8, DEVICE_BUF_SZ);
	DECLARE_KFIFO(write_fifo, u8, DEVICE_BUF_SZ);
};

/* Informație în legătură cu dispozitivele */
static struct uart_device uart[MAX_NUMBER_DEVICES];
static char minors;
static char minor[MAX_NUMBER_DEVICES];

/*
 * uart_interrupt_handle() - funcția pentru tratarea întreruperilor
 * @irq_no:			Numărul întreruperii
 * @dev_id:			Dispozitivul pentru care a venit întreruperea
 * Return:			IRQ_HANDLED la terminare
 *
 * Întreruperea tratează ambele cazuri (de scriere și citire).
 *
 * În cazul unei întreruperi de citire, se opreste acest tip de întreruperi,
 * se citesc datele și se scriu in coada de date.
 * La final se notifică funcția de citire pentru a se trezi.
 *
 * În cazul unei întreruperi de scriere, se opreste acest tip de întreruperi,
 * se iau datele din coadă și se scriu la dispozitivul UART.
 * La final se notifică funcția de scriere pentru a se trezi.
 */
irqreturn_t uart_interrupt_handle(int irq_no, void *dev_id)
{
	struct uart_device *dev = dev_id;
	u8 buffer[COM_DATA_SIZE];
	u8 iir = inb(IIR(dev->baseport));
	u8 count = 0, i = 0;

	if (IIR_NEW_READ(iir)) {
		outb(inb(IER(dev->baseport)) & ~IER_READ, IER(dev->baseport));

		while (inb(LSR(dev->baseport)) & 1 && count < COM_DATA_SIZE)
			buffer[count++] = inb(dev->baseport);

		kfifo_in(&dev->read_fifo, buffer, count);
		dev->read_count = count;

		atomic_set(&dev->read_done, true);
		wake_up_interruptible(&dev->read_queue);
	}

	if (IIR_NEW_WRITE(iir)) {
		outb(inb(IER(dev->baseport)) & ~IER_WRITE, IER(dev->baseport));

		count = kfifo_out(&dev->write_fifo, buffer, COM_DATA_SIZE);

		while (((inb(LSR(dev->baseport)) >> 5) & 1) && i < count)
			outb(buffer[i++], dev->baseport);

		dev->write_count = i;

		atomic_set(&dev->write_done, true);
		wake_up_interruptible(&dev->write_queue);
	}

	return IRQ_HANDLED;
}

/*
 * uart_open() - funcția de deschidere
 * @inode:	Conține date despre dispozitivul UART
 * @file:	Fișierul va conține structura UART
 *
 */
static int uart_open(struct inode *inode, struct file *file)
{
	file->private_data = container_of(inode->i_cdev,
					struct uart_device, chrdev);
	return 0;
}

/*
 * uart_ioctl() - funcția de ioctl
 * @file:	Date despre dispozitivul UART
 * @cmd:	Comanda ioctl
 * @arg:	Argumentul pentru ioctl
 * Return:	0 sau negativ în caz de eroare
 *
 * Când primește o comandă de tipul UART16550_IOCTL_SET_LINE copiază din
 * spațiul utilizator parametrii transmisiei UART, activează biții
 * corespunzători (condiției de oprire la transmisie) ratei și contorului
 * ratei de transmisie.
 */
static long uart_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct uart16550_line_info info;
	struct uart_device *dev = (struct uart_device *)file->private_data;

	if (cmd == UART16550_IOCTL_SET_LINE) {
		if (copy_from_user(&info, (const void *)arg, sizeof(info)))
			return -EFAULT;

		outb(inb(LCR(dev->baseport)) | DLAB, LCR(dev->baseport));
		outb(info.baud, dev->baseport);

		outb(info.len | info.stop | info.par, LCR(dev->baseport));

		return 0;
	}

	return -EINVAL;
}

/*
 * uart_read() - funcția citire de pe un dispozitiv UART
 * @file:		Fișierul din care se face citirea
 * @user_buffer:	Depozitul în care vor fi puse date pentru utilizator
 * @size:		Dimensiunea ce trebuie scrisă
 * @offset:		Deplasamentul de unde să înceapă scrierea
 * Return:		numărul de elemente citite sau negativ în caz de eroare
 *
 * Așteaptă să fie anunțată că au sosit date de la dispozitivul UART și apoi
 * golește datele primite din coadă în depozitul utilizatorului. La final se
 * reactivează întreruperile UART-ului.
 */
static int uart_read(struct file *file, char *user_buffer,
			size_t size, loff_t *offset)
{
	struct uart_device *dev = file->private_data;
	int retval = 0;

	if (!size)
		return 0;

	if (wait_event_interruptible(dev->read_queue,
		atomic_cmpxchg(&dev->read_done, false, false) == true))
		return -ERESTARTSYS;

	if (kfifo_to_user(&dev->read_fifo, user_buffer, size, &retval))
		return -EFAULT;

	atomic_set(&dev->read_done, false);

	outb(inb(IER(dev->baseport)) | IER_READ, IER(dev->baseport));

	return retval;
}

/*
 * uart_write() - funcția de scriere pe un dispozitiv UART
 * @file:		Fișierul în care se face scrierea
 * @user_buffer:	Depozitul în care vin date de la utilizator
 * @size:		Dimensiunea ce trebuie scrisă
 * @offset:		Deplasamentul de unde să înceapă scrierea
 * Return:		numărul de elemente scrise sau negativ în caz de eroare
 *
 * Copiază maxim 14 octeți din spațiul utilizator în coada de stocare și
 * notifică dispozitivul UART că poate să trimită din nou întreruperi.
 * Operațiile sunt atomice pentru a garanta corectitudinea evenimentelor.
 */
static int uart_write(struct file *file, const char *user_buffer,
			size_t size, loff_t *offset)
{
	struct uart_device *dev = file->private_data;
	size_t max_size = size > COM_DATA_SIZE ? COM_DATA_SIZE : size;
	int retval = 0;

	if (!size)
		return 0;

	if (kfifo_from_user(&dev->write_fifo, user_buffer, max_size, &retval))
		return -EFAULT;

	atomic_set(&dev->write_done, false);

	outb(inb(IER(dev->baseport)) | IER_WRITE, IER(dev->baseport));

	if (wait_event_interruptible(dev->write_queue,
		atomic_cmpxchg(&dev->write_done, false, false) == true))
		return -ERESTARTSYS;

	return dev->write_count;
}

/* Structură cu funcțiile (operațiile) ioctl pe fișiere */
static const struct file_operations uart_fops = {
	.owner          = THIS_MODULE,
	.open           = uart_open,
	.read           = uart_read,
	.write          = uart_write,
	.unlocked_ioctl = uart_ioctl
};

/*
 * uart_init_device() - funcția de inițializare a unui dispozitiv UART
 * @baseport:		Adresa de bază a dispozitivului
 * @irq:		IRQ-ul dispozitivului
 * @device_id:		Minorul dispozitivului
 * Return:		0 dacă a reusit sau negativ în caz de eroare
 *
 * Creează un nou dispozitiv UART, îl adaugă în mulțimea de dispozitive
 * caracter a sistemului, îi atribuie regiunea și IRQ-ul, inițializează
 * câmpurile și pune biții corespunzători în regiștri pentru a activa structuri
 * FIFO, linia pe care vor circula date și dimensiunea lor la 14 octeți.
 */
static int uart_init_device(int baseport, int irq, int device_id)
{
	int retval = 0;

	retval = cdev_add(&uart[device_id].chrdev, MKDEV(major, device_id), 1);
	if (retval < 0)
		return retval;

	if (!request_region(baseport, COM_NR_PORTS, MODULE_NAME))
		return -EBUSY;

	retval = request_irq(irq, uart_interrupt_handle, IRQF_SHARED,
				MODULE_NAME, &uart[device_id]);
	if (retval < 0)
		return retval;

	uart[device_id].baseport = baseport;

	atomic_set(&uart[device_id].read_done, false);
	atomic_set(&uart[device_id].write_done, false);

	uart[device_id].read_count = 0;
	uart[device_id].write_count = 0;

	init_waitqueue_head(&uart[device_id].read_queue);
	init_waitqueue_head(&uart[device_id].write_queue);

	INIT_KFIFO(uart[device_id].read_fifo);
	INIT_KFIFO(uart[device_id].write_fifo);

	cdev_init(&uart[device_id].chrdev, &uart_fops);

	outb(ERDAI, IER(baseport));
	outb(OUT_LINE, MCR(baseport));
	outb(FIFO_OPTS, FCR(baseport));

	return 0;
}

/*
 * uart_init() - funcția de inițializare a regiunii și dispozitivelor
 * Return:	0 dacă a reusit sau negativ în caz de eroare
 *
 * Activează minorii în funcție de opțiunea primită, înregistrează regiunea
 * pentru dispozitivul caracter și inițializează dispozitivele UART cu ajutorul
 * funcției uart_init_device().
 */
static int uart_init(void)
{
	int retval = 0;

	switch (option) {
	case OPTION_BOTH:
		minors = 2;
		minor[MINOR_COM1] = 1;
		minor[MINOR_COM2] = 1;
		break;

	case OPTION_COM1:
		minors = 1;
		minor[MINOR_COM1] = 1;
		minor[MINOR_COM2] = 0;
		break;

	case OPTION_COM2:
		minors = 1;
		minor[MINOR_COM1] = 0;
		minor[MINOR_COM2] = 1;
		break;

	default:
		return -EINVAL;
	}

	retval = register_chrdev_region(MKDEV(major, minors_offset),
					minors, MODULE_NAME);
	if (retval < 0)
		return retval;

	if (minor[MINOR_COM1]) {
		retval = uart_init_device(COM1_BASEPORT, COM1_IRQ, MINOR_COM1);
		if (retval < 0)
			goto unregister_devices;
	}

	if (minor[MINOR_COM2]) {
		retval = uart_init_device(COM2_BASEPORT, COM2_IRQ, MINOR_COM2);
		if (retval < 0)
			goto unregister_devices;
	}

	return 0;

unregister_devices:
	unregister_chrdev_region(MKDEV(major, minors_offset), minors);
	return retval;
}

/*
 * uart_remove_device() - funcția de ștergere a unui dispozitiv UART
 * @baseport:		Adresa de bază a dispozitivului
 * @irq:		IRQ-ul dispozitivului
 * @device_id:		Minorul dispozitivului
 *
 * Golește regiștrii folosiți pentru transmisia de date, eliberează
 * regiunea ocupată și șterge dispozitivul caracter din sistem.
 */
static inline void uart_remove_device(int baseport, int irq, int device_id)
{
	free_irq(irq, &uart[device_id]);
	release_region(baseport, COM_NR_PORTS);
	cdev_del(&uart[device_id].chrdev);
}

/*
 * uart_exit() - funcția de eliberare a regiunii și dispozitivelor
 *
 * La ieșirea din modul, șterge dispozitivele UART și regiunea alocată.
 */
static void uart_exit(void)
{
	if (minor[MINOR_COM1])
		uart_remove_device(COM1_BASEPORT, COM1_IRQ, MINOR_COM1);

	if (minor[MINOR_COM2])
		uart_remove_device(COM2_BASEPORT, COM2_IRQ, MINOR_COM2);

	unregister_chrdev_region(MKDEV(major, minors_offset), minors);
}

module_init(uart_init);
module_exit(uart_exit);

MODULE_DESCRIPTION("Linux UART Driver");
MODULE_AUTHOR("Cezar Crăciunoiu <cezar.craciunoiu@gmail.com>");
MODULE_AUTHOR("Călin Jugănaru	<calin_vlad.juganaru@stud.acs.upb.ro>");
MODULE_LICENSE("GPL v2");
